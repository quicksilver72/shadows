#!/usr/bin/env bash
# passgen.sh — Generates 3 Webster-based secure passwords with progress bar
set -euo pipefail

SPECIAL='!@#$%&*=+<>?'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR="$SCRIPT_DIR/lib/webster_words.py"

# ========== Utility: Random Integer ==========
rand_index() {
  local n=$1
  od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]' | awk -v n="$n" '{print ($1 % n)}'
}

# ========== Utility: Substitution ==========
substitute() {
  local s="$1" out="" i ch repl
  for ((i=0; i<${#s}; i++)); do
    ch="${s:i:1}"
    case "$ch" in
      E) repl='3' ;; A) repl='4' ;; a) repl='@' ;; l) repl='1' ;;
      L) repl='[' ;; S) repl='5' ;; I) repl=']' ;; Z) repl='2' ;;
      t) repl='+' ;; T) repl='7' ;; G) repl='6' ;; B) repl='8' ;;
      C) repl='(' ;; c) repl='<' ;; *) repl='' ;;
    esac
    if [ -n "$repl" ] && [ $(( $(od -An -N1 -tu1 /dev/urandom | tr -d ' ') % 3 )) -eq 0 ]; then
      out+="$repl"
    else
      out+="$ch"
    fi
  done
  printf '%s' "$out"
}

# ========== Utility: Loading Bar ==========
progress_bar() {
  local progress=$1 total=$2 width=40
  local percent=$(( progress * 100 / total ))
  local filled=$(( width * progress / total ))
  local empty=$(( width - filled ))
  printf "\r["
  printf "%0.s#" $(seq 1 "$filled")
  printf "%0.s-" $(seq 1 "$empty")
  printf "] %3d%%" "$percent"
}

progress_step() {
  local message=$1 step=$2 total=$3
  printf "\n\033[1;36m[Step %d/%d]\033[0m %s\n" "$step" "$total" "$message"
}

# ========== PHASE 1: Initialization ==========
total_steps=4
step=1
progress_step "Initializing secure random environment..." $step $total_steps
for i in $(seq 1 10); do
  progress_bar "$i" 10; sleep 0.05
done
printf "\n"

# ========== PHASE 2: Generate words ==========
step=$((step+1))
progress_step "Invoking Webster word generator..." $step $total_steps

if ! command -v python3 >/dev/null; then
  echo "❌ Error: Python 3 not found. Install Python 3 to continue." >&2
  exit 1
fi

# Capture Python process output with progress bar animation
{
  python3 "$GENERATOR" > /tmp/webster_words.$$ &
  pid=$!
  spin=('|' '/' '-' '\')
  i=0
  while kill -0 $pid 2>/dev/null; do
    printf "\rGenerating words... %s" "${spin[i++ % 4]}"
    sleep 0.1
  done
  wait $pid
  printf "\rGenerating words... ✅\n"
} 2>/dev/null

mapfile -t WORDS < /tmp/webster_words.$$
rm -f /tmp/webster_words.$$

# ========== PHASE 3: Process passwords ==========
step=$((step+1))
progress_step "Constructing and securing final passwords..." $step $total_steps
PASSWORDS=()
for base in "${WORDS[@]}"; do
  progress_bar ${#PASSWORDS[@]} 3
  d1=$(( $(rand_index 10) ))
  d2=$(( $(rand_index 10) ))
  s_char="${SPECIAL:$(rand_index ${#SPECIAL}):1}"
  raw="${base}${d1}${d2}${s_char}"
  PASSWORDS+=("$(substitute "$raw")")
  sleep 0.2
done
progress_bar 3 3
printf "\n"

# ========== PHASE 4: Output and Cleanup ==========
step=$((step+1))
progress_step "Displaying final passwords..." $step $total_steps
sleep 0.3

if [ -w /dev/tty ]; then
  printf '\n🔐  YOUR ONE-TIME PASSWORDS:\n\n' > /dev/tty
  for pw in "${PASSWORDS[@]}"; do
    printf '    %s\n' "$pw" > /dev/tty
  done
  printf '\nPress ENTER to clear and return to shell...' > /dev/tty
  read -r _ < /dev/tty
else
  printf '\n🔐  YOUR ONE-TIME PASSWORDS:\n\n'
  for pw in "${PASSWORDS[@]}"; do
    printf '    %s\n' "$pw"
  done
  printf '\n'
  read -r _
fi

printf "\n"
for i in $(seq 1 10); do
  progress_bar "$i" 10; sleep 0.04
done
printf " ✅\n"
sleep 0.2

clear
unset PASSWORDS
printf "\033[1;32mAll processes complete. Session cleared.\033[0m\n"
exit 0
