#!/usr/bin/env python3
"""
tbreak4.py — Educational 4-digit PIN search benchmark simulator

Features:
 - Multiple strategies: numeric, reverse, random, common-first, pattern-first, probability (advanced).
 - Interactive CLI prompting when run without flags.
 - Safe: purely local, in-memory comparison.
 - Simulated defenses: delay, lockout, exponential backoff, per-method and global timeouts.
 - Informative summary table.

Usage examples:
  python3 break4.py                     # interactive walkthrough
  python3 break4.py --run-all           # run all strategies non-interactively
  python3 break4.py -m probability -t 1234 --simulate-delay 0.001

Author: quicksilver
"""

from __future__ import annotations
import argparse, random, math, sys, time
from typing import Iterable, Optional, Dict, Any, List, Tuple

# ----------------------------------------------------------------------
# Training sets for heuristics
# ----------------------------------------------------------------------
COMMON_PINS = [
    "1234","0000","1111","1212","7777","1004","2000","6969","4444","2222",
    "9999","3333","5555","6666","1122","1313","8888","4321","2001","1010",
    "1999","1425","2536","3625","3210","1004","1452","2563","5241","4125",
    "5236","5214","6325"
]

SIMPLE_PATTERNS = [
    "0000","1111","2222","3333","4444","5555","6666","7777","8888","9999",
    "0123","1234","2345","3456","4567","5678","6789",
    "9876","8765","7654","6543","5432","4321",
    "1212","1000","2000","2020"
]

# ----------------------------------------------------------------------
# Generator methods
# ----------------------------------------------------------------------
def gen_numeric(): yield from (f"{i:04d}" for i in range(10000))
def gen_reverse_numeric(): yield from (f"{i:04d}" for i in range(9999,-1,-1))
def gen_random(seed=None):
    codes=[f"{i:04d}" for i in range(10000)]
    rnd=random.Random(seed); rnd.shuffle(codes)
    yield from codes
def gen_common_first():
    seen=set()
    for p in COMMON_PINS:
        if len(p)==4 and p.isdigit(): seen.add(p); yield p
    for c in gen_numeric():
        if c not in seen: yield c
def gen_pattern_first():
    seen=set()
    for p in SIMPLE_PATTERNS:
        if len(p)==4 and p.isdigit(): seen.add(p); yield p
    for c in gen_numeric():
        if c not in seen: yield c

# ----------------------------------------------------------------------
# Advanced Markov Model (Position-Aware)
# ----------------------------------------------------------------------
def build_markov_model(training: Iterable[str]):
    """Build position-specific unigram and bigram distributions."""
    unigram = {pos: {str(d): 1 for d in range(10)} for pos in range(4)}  # Laplace smoothing
    bigram  = {pos: {} for pos in range(1,4)}
    for pin in training:
        if len(pin)!=4 or not pin.isdigit(): continue
        for pos,d in enumerate(pin):
            unigram[pos][d]+=1
        for pos in range(1,4):
            pair=pin[pos-1:pos+1]
            bigram[pos][pair]=bigram[pos].get(pair,1)+1
    # normalize
    for pos in range(4):
        total=sum(unigram[pos].values())
        for d in unigram[pos]: unigram[pos][d]/=total
    for pos in range(1,4):
        total=sum(bigram[pos].values())
        for p in bigram[pos]: bigram[pos][p]/=total
    return unigram,bigram

def score_pin_markov(pin:str,uni,bi,
                     w_pos=1.0,w_pair=1.2,w_pat=1.0)->float:
    """Compute PIN score via Markov position/bigram + pattern detection."""
    s=0.0
    # position-weighted digits
    for pos,d in enumerate(pin):
        p=uni[pos].get(d,1e-6)
        s+=w_pos*math.log(p)
    # bigrams by position
    for pos in range(1,4):
        pair=pin[pos-1:pos+1]
        q=bi[pos].get(pair,1e-8)
        s+=w_pair*math.log(q)
    # dynamic pattern bonuses
    bonus=0.0
    if pin in COMMON_PINS: bonus+=5
    if pin in SIMPLE_PATTERNS: bonus+=3
    if len(set(pin))<=2: bonus+=2
    if pin==pin[::-1]: bonus+=1.5  # palindrome
    diff=[int(pin[i+1])-int(pin[i]) for i in range(3)]
    if all(d==1 for d in diff) or all(d==-1 for d in diff): bonus+=2.5
    if pin[0]==pin[2] and pin[1]==pin[3]: bonus+=1.5  # mirrored halves
    s+=w_pat*bonus
    return s

def gen_probability_markov(seed=None):
    """Generate all PINs ranked by Markov likelihood score."""
    training=COMMON_PINS+SIMPLE_PATTERNS
    uni,bi=build_markov_model(training)
    scored=[(score_pin_markov(f"{i:04d}",uni,bi),f"{i:04d}") for i in range(10000)]
    scored.sort(reverse=True)
    for _,pin in scored: yield pin

# ----------------------------------------------------------------------
# Core brute-force engine (same as before)
# ----------------------------------------------------------------------
def attempt_search(generator,target_pin,simulate_delay=0.0,
                   lockout_after=None,lockout_duration=0.0,
                   exponential_backoff=False,per_method_timeout=None,
                   progress_interval=1000,verbose=False)->Dict[str,Any]:
    start=time.perf_counter(); att=0; locks=0; next_unlock=0.0; mult=1.0
    for code in generator:
        el=time.perf_counter()-start
        if per_method_timeout and el>=per_method_timeout:
            return dict(found=False,attempts=att,elapsed=el,
                        found_pin=None,reason="timeout",lockouts=locks)
        if next_unlock and el<next_unlock:
            rem=next_unlock-el
            if per_method_timeout and el+rem>=per_method_timeout:
                return dict(found=False,attempts=att,elapsed=el,
                            found_pin=None,reason="timeout_during_lockout",lockouts=locks)
            time.sleep(rem)
        if simulate_delay:
            remain=per_method_timeout-(time.perf_counter()-start) if per_method_timeout else None
            if remain and remain<=0: break
            time.sleep(simulate_delay if not remain else min(simulate_delay,remain))
        att+=1
        if verbose and att%progress_interval==0:
            el=time.perf_counter()-start
            rate=att/el if el>0 else float('inf')
            print(f"[progress] attempts={att}, elapsed={el:.2f}s, rate={rate:.0f}/s")
        if code==target_pin:
            el=time.perf_counter()-start
            return dict(found=True,attempts=att,elapsed=el,
                        found_pin=code,reason="found",lockouts=locks)
        if lockout_after and att%lockout_after==0:
            locks+=1
            dur=lockout_duration*mult
            next_unlock=(time.perf_counter()-start)+dur
            if exponential_backoff: mult*=2
    el=time.perf_counter()-start
    return dict(found=False,attempts=att,elapsed=el,
                found_pin=None,reason="exhausted",lockouts=locks)

# ----------------------------------------------------------------------
# Run a single strategy
# ----------------------------------------------------------------------
def run_strategy(name,args,target)->Dict[str,Any]:
    print(f"\n--- Running strategy: {name} ---")
    gen=STRATEGIES[name](args)
    r=attempt_search(gen,target,args.simulate_delay,args.lockout_after,
                     args.lockout_duration,args.exponential_backoff,
                     args.method_timeout,args.progress_interval,args.verbose)
    att=r["attempts"]; el=r["elapsed"]; rate=att/el if el>0 else float('inf')
    print(f"Strategy: {name:15s}  Result: {r['reason']:12s}  "
          f"Attempts: {att:6d}  Elapsed: {el:8.4f}s  Rate: {rate:8.0f}/s  "
          f"Lockouts: {r.get('lockouts',0)}")
    return dict(name=name,result=r,attempts=att,elapsed=el,rate=rate)

# ----------------------------------------------------------------------
# User interaction helpers
# ----------------------------------------------------------------------
def ask_choice(prompt,choices,default=None):
    opts="/".join(choices)+(f" (default {default})" if default else "")
    while True:
        a=input(f"{prompt} [{opts}]: ").strip()
        if not a and default: return default
        for c in choices:
            if a.lower()==c.lower(): return c
        print("Invalid choice.")
def ask_yesno(prompt,default=False):
    d="Y/n" if default else "y/N"
    while True:
        a=input(f"{prompt} [{d}]: ").strip().lower()
        if not a: return default
        if a in ("y","yes"): return True
        if a in ("n","no"): return False
def ask_int(prompt,default=None,allow_empty=False):
    while True:
        a=input(f"{prompt}{' (Enter to skip)' if allow_empty else ''}: ").strip()
        if not a:
            if allow_empty: return default
            if default is not None: return default
            print("Value required."); continue
        try: return int(a)
        except: print("Enter integer.")
def ask_float(prompt,default=None,allow_empty=False):
    while True:
        a=input(f"{prompt}{' (Enter to skip)' if allow_empty else ''}: ").strip()
        if not a:
            if allow_empty: return default
            if default is not None: return default
            print("Value required."); continue
        try: return float(a)
        except: print("Enter number.")

# ----------------------------------------------------------------------
# Parser and strategies dictionary
# ----------------------------------------------------------------------
def build_parser():
    p=argparse.ArgumentParser(prog="break4_v2.py",
        description="Educational 4-digit PIN search simulator (local-only, Markov).")
    p.add_argument("--interactive",action="store_true",help="Force interactive prompts.")
    p.add_argument("--target","-t",type=str,default=None,help="Target 4-digit PIN (random if omitted).")
    p.add_argument("--mode","-m",choices=[],default="probability",
                   help="Strategy to run (ignored with --run-all).")
    p.add_argument("--run-all",action="store_true",help="Run all strategies sequentially.")
    p.add_argument("--seed",type=int,default=None,help="Seed for deterministic random mode.")
    p.add_argument("--simulate-delay",type=float,default=0.0,help="Simulated delay per attempt.")
    p.add_argument("--lockout-after",type=int,default=None,help="Lockout after N attempts.")
    p.add_argument("--lockout-duration",type=float,default=0.0,help="Lockout duration (s).")
    p.add_argument("--exponential-backoff",action="store_true",help="Double lockout durations.")
    p.add_argument("--method-timeout",type=float,default=None,help="Per-method timeout (s).")
    p.add_argument("--global-timeout",type=float,default=None,help="Global timeout (s).")
    p.add_argument("--progress-interval",type=int,default=1000,help="Progress message interval.")
    p.add_argument("--verbose",action="store_true",help="Verbose output.")
    return p

STRATEGIES = {
    "numeric":lambda a:gen_numeric(),
    "reverse":lambda a:gen_reverse_numeric(),
    "random":lambda a:gen_random(a.seed if a else None),
    "common-first":lambda a:gen_common_first(),
    "pattern-first":lambda a:gen_pattern_first(),
    "probability":lambda a:gen_probability_markov()
}

# update parser choices dynamically
parser_for_choices = build_parser()
parser_for_choices._actions[2].choices = list(STRATEGIES.keys())

# ----------------------------------------------------------------------
# Main program
# ----------------------------------------------------------------------
def main():
    parser=parser_for_choices
    args,_=parser.parse_known_args()
    interactive=args.interactive or len(sys.argv)==1

    print("LEGAL / ETHICAL NOTICE:")
    print("  This tool is for educational use only. It simulates PIN search locally.\n")

    if interactive:
        print("Interactive configuration:\n")
        if ask_choice("Target source",["Generate","Input"],"Generate")=="Input":
            while True:
                p=input("Enter 4-digit target PIN: ").strip()
                if len(p)==4 and p.isdigit(): target=p; break
                print("Invalid PIN.")
        else:
            target=f"{random.SystemRandom().randint(0,9999):04d}"
            print(f"Generated target PIN: {target}")
        strat=ask_choice("Strategy (single/all)",["single","all"],"single")
        args.run_all=(strat=="all")
        if not args.run_all:
            args.mode=ask_choice("Select strategy",list(STRATEGIES.keys()),"probability")
        args.simulate_delay=ask_float("Simulated delay per attempt (s)",0.0,True) or 0.0
        args.lockout_after=ask_int("Lockout after N attempts (0=off)",None,True)
        if args.lockout_after==0: args.lockout_after=None
        args.lockout_duration=ask_float("Lockout duration (s)",0.0,True) or 0.0
        args.exponential_backoff=ask_yesno("Use exponential backoff?",False)
        args.method_timeout=ask_float("Per-method timeout (s)",None,True)
        args.global_timeout=ask_float("Global timeout (s)",None,True)
        args.progress_interval=ask_int("Progress interval",1000,True) or 1000
        args.seed=ask_int("Seed",None,True)
        args.verbose=ask_yesno("Verbose progress?",False)
        args.target=target
    else:
        if args.target is None:
            args.target=f"{random.SystemRandom().randint(0,9999):04d}"
            print(f"[info] Generated random target: {args.target}")
        target=args.target

    start=time.perf_counter(); results=[]
    strats=list(STRATEGIES.keys()) if args.run_all else [args.mode]
    for s in strats:
        if args.global_timeout and (time.perf_counter()-start)>=args.global_timeout:
            print("[info] Global timeout reached; stopping."); break
        results.append(run_strategy(s,args,target))
        if not args.run_all and results[-1]["result"]["reason"]=="found": break

    total=time.perf_counter()-start
    print("\n"+"="*72)
    print("SUMMARY (comparative)")
    print(f" Target: {target}   Total elapsed: {total:.4f}s")
    print(f"{'Strategy':<15} {'Reason':<12} {'Attempts':>8} {'Elapsed(s)':>12} "
          f"{'Rate/s':>10} {'Lockouts':>9}")
    for r in results:
        name=r.get("name","?")
        res=r.get("result",{})
        reason=res.get("reason","unknown")
        att=r.get("attempts",0)
        el=r.get("elapsed",0.0)
        rate=r.get("rate",0.0)
        locks=res.get("lockouts",0)
        print(f"{name:<15} {reason:<12} {att:8d} {el:12.4f} {rate:10.0f} {locks:9d}")
    print("="*72)
    print("Notes:")
    print(" - 'probability' now uses a position-aware Markov model with dynamic pattern detection.")
    print(" - Lockouts/backoffs demonstrate the impact of throttling on brute-force speed.")
    print(" - Safe, local, educational only. Never use on real systems without authorization.")
    print("="*72)

if __name__=="__main__":
    main()
