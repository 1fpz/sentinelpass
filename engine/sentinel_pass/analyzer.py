"""Local password analysis. Estimates are deliberately conservative and explainable."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import math,re

COMMON={"password","password1","123456","12345678","qwerty","qwerty123","letmein","admin","welcome","iloveyou","monkey","dragon","football","abc123"}
@dataclass(frozen=True)
class Finding:
    severity:str; title:str; detail:str
@dataclass(frozen=True)
class CrackModel:
    online:str; offline_slow_hash:str; fast_gpu:str
@dataclass(frozen=True)
class Report:
    score:int; label:str; entropy:float; guesses:float; length:int; findings:list[Finding]; crack:CrackModel
    def to_dict(self): return {**asdict(self),"guesses":self.guesses}

def leet(s:str)->str:
    return s.lower().translate(str.maketrans({"@":"a","4":"a","3":"e","1":"i","!":"i","0":"o","5":"s","7":"t"}))

def human_seconds(seconds:float)->str:
    if math.isinf(seconds): return "effectively infeasible"
    units=((31557600,"years"),(86400,"days"),(3600,"hours"),(60,"minutes"),(1,"seconds"))
    for size,name in units:
        if seconds>=size:return f"{seconds/size:.1f} {name}"
    return "<1 second"

def analyze(password:str)->Report:
    lower=bool(re.search(r"[a-z]",password)); upper=bool(re.search(r"[A-Z]",password)); digit=bool(re.search(r"\d",password)); symbol=bool(re.search(r"[^A-Za-z0-9]",password))
    pool=(26 if lower else 0)+(26 if upper else 0)+(10 if digit else 0)+(33 if symbol else 0)
    entropy=len(password)*math.log2(max(pool,1))
    f=[]; n=leet(password)
    if n in COMMON:f.append(Finding("high","Common password","This value or its leetspeak-normalized form is highly predictable."))
    if password and len(set(password))==1:f.append(Finding("high","Repeated character","A repeated character collapses the effective search space."))
    if re.match(r"^(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)",password,re.I):f.append(Finding("high","Sequence or keyboard pattern","Sequences and keyboard walks are common cracker candidates."))
    if re.match(r"^(19|20)\d{2}",password) or re.search(r"\d{4}$",password):f.append(Finding("medium","Date/year pattern","Year-like suffixes and dates are common password mutations."))
    if len(password)<12:f.append(Finding("medium","Short password","Prefer a long passphrase; length matters more than cosmetic complexity."))
    if len(password)<16 and sum((lower,upper,digit,symbol))<=2:f.append(Finding("low","Narrow character set","A small alphabet reduces the theoretical search space."))
    if any(fx.severity=="high" for fx in f):entropy=min(entropy,28)
    elif any(fx.severity=="medium" for fx in f):entropy=min(entropy,55)
    guesses=min(2**min(entropy,100),1e30)
    score=1 if entropy<28 else 2 if entropy<40 else 3 if entropy<60 else 4
    if any(x.severity=="high" for x in f):score=1
    if len(password)>=20 and not any(x.severity=="high" for x in f):score=4
    label=("Very weak","Weak","Fair","Strong","Very strong")[score]
    return Report(score,label,entropy,guesses,len(password),f,CrackModel(human_seconds(guesses/100),human_seconds(guesses/1e4),human_seconds(guesses/1e9)))
