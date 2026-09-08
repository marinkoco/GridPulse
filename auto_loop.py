import subprocess
import re
import sys
import shlex

STATE_FILE = "project_state.md"

def get_next_task():
    """Reads project_state.md and finds the first unchecked task."""
    try:
        with open(STATE_FILE, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {STATE_FILE} not found. Have Pro generate it first!")
        sys.exit(1)
        
    match = re.search(r'^- \[ \] (.*)$', content, re.MULTILINE)
    if match:
        return match.group(1), match.group(0)
    return None, None

def mark_task_complete(task_line):
    """Replaces '- [ ]' with '- [x]' and saves the file."""
    with open(STATE_FILE, "r") as f:
        content = f.read()
    
    completed_line = task_line.replace("- [ ]", "- [x]", 1)
    new_content = content.replace(task_line, completed_line, 1)
    
    with open(STATE_FILE, "w") as f:
        f.write(new_content)

def get_recent_history():
    """Extracts the last 2 completed tasks to give the Doer context."""
    with open(STATE_FILE, "r") as f:
        content = f.read()
    
    completed = re.findall(r'^- \[x\] (.*)$', content, re.MULTILINE)
    
    if not completed:
        return "No previous steps completed yet."
        
    recent = completed[-2:]
    return "\n".join([f"✓ {t}" for t in recent])

def run_agent(model, prompt, effort="high", skip_perms=False):
    """
    Executes the Antigravity CLI using raw shell execution.
    shlex.quote() safely wraps the massive multi-line prompt so bash doesn't choke.
    """
    safe_prompt = shlex.quote(prompt)
    
    # Build the exact bash command, including the required --effort flag
    cmd_str = f"rtk agy --model {model} --effort {effort} -p {safe_prompt}"
    
    if skip_perms:
        cmd_str += " --dangerously-skip-permissions"
        
    # shell=True bypasses python's strict list parsing and runs it natively
    result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
    
    # Diagnostic check to catch silent crashes
    if not result.stdout.strip():
        print(f"\n[CRITICAL ERROR] The CLI tools failed silently!")
        print(f"COMMAND START: {cmd_str[:80]}... [truncated]")
        print(f"ERROR LOG (STDERR): {result.stderr.strip()}\n")
        return "REJECTED: Internal CLI Error"
        
    return result.stdout.strip()

# ==========================================
# THE MASTER LOOP
# ==========================================
def main():
    print("🚀 Starting Autonomous Agent Loop...")

    while True:
        task, exact_line = get_next_task()
        if not task:
            print("\n🎉 All tasks in project_state.md are complete!")
            break
            
        print(f"\n⚙️ CURRENT TASK: {task}")
        
        attempts = 1
        max_attempts = 4
        approved = False
        feedback = ""
        
        while attempts <= max_attempts:
            print(f"  ▶️ Attempt {attempts} (Doer: Flash)...")
            
            recent_history = get_recent_history()
            
            doer_prompt = f"""
You are executing the next step in our project plan.

RECENTLY COMPLETED STEPS:
{recent_history}

CURRENT TASK:
{task}

FEEDBACK TO FIX: {feedback if feedback else 'None'}

CRITICAL INSTRUCTION:
Do NOT write code blindly. You have Serena MCP tools available.
1. FIRST, use your `list_dir` or `read_file` tools to inspect the files created in the recently completed steps. Or use `git log -n 3` to understand recent changes.
2. Analyze their variables, classes, and structure.
3. THEN, execute the necessary code, terminal commands, or file creations to complete the Current Task so it perfectly integrates with the existing codebase.
4. SECURITY ENFORCEMENT: NEVER hardcode real API keys, passwords, or secrets. When writing tests for external APIs (like Tailscale), you MUST use `unittest.mock` or `pytest-mock` to mock the HTTP responses. 
5. TEMPLATE SECURITY: When generating template files like `.env.example`, ONLY use obvious, generic placeholders (e.g., `YOUR_API_KEY_HERE`). NEVER generate realistic-looking fake keys that match actual API key patterns (like `tskey-api-...`).
"""
            # Call Flash with effort="high" and permissions enabled
            draft = run_agent("gemini-3.8-flash", doer_prompt, effort="high", skip_perms=True)
            
            print(f"  ▶️ Checking work (Checker: Pro)...")
            
            checker_prompt = f"""
Audit the workspace to see if this task was completed properly: "{task}"
If the task is fully satisfied, output exactly 'APPROVED'.
If it fails, output 'REJECTED' and explain what the developer must fix.
Developer's output report: 
{draft}
"""
            # Call Pro with effort="high" and permissions enabled to allow auditing commands
            eval_result = run_agent("gemini-3.1-pro", checker_prompt, effort="high", skip_perms=True)
            
            if "APPROVED" in eval_result:
                print("  ✅ APPROVED!")
                mark_task_complete(exact_line)
                
                print("  📦 Committing and pushing step to GitHub...")
                commit_msg = f"Completed: {task}"
                subprocess.run(["git", "add", "."], capture_output=True)
                subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True)
                subprocess.run(["git", "push", "-u", "origin", "main"], capture_output=True)
                
                approved = True
                break
            else:
                print(f"  ❌ REJECTED! Passing feedback back to Doer...\n  Feedback: {eval_result}")
                feedback = eval_result
                attempts += 1
                
        if not approved:
            print(f"\n🛑 FAILED: The agents got stuck on '{task}'.")
            print("Halting loop so you can manually intervene. project_state.md is unchanged.")
            sys.exit(1)

if __name__ == "__main__":
    main()