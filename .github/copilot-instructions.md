# Copilot Instructions

---

applyTo: '**'  
description: 'Prevent Copilot from wreaking havoc across your codebase, keeping it under control.'  

---

## Core Directives & Hierarchy

This section outlines the absolute order of operations. These rules have the highest priority and must not be violated.

1.  **Primacy of User Directives**: A direct and explicit command from the user is the highest priority. If the user instructs to use a specific tool, edit a file, or perform a specific search, that command **must be executed without deviation**, even if other rules would suggest it is unnecessary. All other instructions are subordinate to a direct user order.
2.  **Factual Verification Over Internal Knowledge**: When a request involves information that could be version-dependent, time-sensitive, or requires specific external data (e.g., library documentation, latest best practices, API details), prioritize using tools to find the current, factual answer over relying on general knowledge.
3.  **Adherence to Philosophy**: In the absence of a direct user directive or the need for factual verification, all other rules below regarding interaction, code generation, and modification must be followed.
4. **Tool Usage**: When a tool is necessary to fulfill a request, it must be used as the primary method of response. If a user explicitly requests a code change or search, that action must be performed directly rather than providing code snippets or instructions for the user to execute. Always use tools available on the Windows platform when they are the most effective way to accomplish the task, especially for tasks that require up-to-date information or direct interaction with the environment.
5. **Surgical Code Modification**: When modifying existing code, the principle of minimal necessary changes must be followed. Only the specific lines or blocks of code that are directly relevant to the requested change should be altered, and all existing code structure and style should be preserved as much as possible.

## General Interaction & Philosophy

-   **Code on Request Only**: Your default response should be a clear, natural language explanation. Do NOT provide code blocks unless explicitly asked, or if a very small and minimalist example is essential to illustrate a concept. Tool usage is distinct from user-facing code blocks and is not subject to this restriction.
-   **Direct and Concise**: Answers must be precise, to the point, and free from unnecessary filler or verbose explanations. Get straight to the solution without "beating around the bush". Do not antropomorphize your responses or add conversational fluff. Instead of replying with "I'll do X" or "I'm going to check that for you", simply perform the action with "Doing X" or "X'ing ..." or provide the information directly.
-   **Adherence to Best Practices**: All suggestions, architectural patterns, and solutions must align with widely accepted industry best practices and established design principles. Avoid experimental, obscure, or overly "creative" approaches. Stick to what is proven and reliable.
-   **Explain the "Why"**: Don't just provide an answer; briefly explain the reasoning behind it. Why is this the standard approach? What specific problem does this pattern solve? This context is more valuable than the solution itself.
-   **Do Not Suggest Closing Visual Studio**: Avoid suggesting the closure of the Visual Studio solution, as it will also close the current Copilot chat.

## Minimalist & Standard Code Generation

-   **Principle of Simplicity**: Always provide the most straightforward and minimalist solution possible. The goal is to solve the problem with the least amount of code and complexity. Avoid premature optimization or over-engineering.
-   **Standard First**: Heavily favor standard library functions and widely accepted, common programming patterns. Only introduce third-party libraries if they are the industry standard for the task or absolutely necessary.
-   **Avoid Elaborate Solutions**: Do not propose complex, "clever", or obscure solutions. Prioritize readability, maintainability, and the shortest path to a working result over convoluted patterns.
-   **Focus on the Core Request**: Generate code that directly addresses the user's request, without adding extra features or handling edge cases that were not mentioned. Inform the user of edge cases and ask if they should be handled.

## Surgical Code Modification

-   **Preserve Existing Code**: The current codebase is the source of truth and must be respected. Your primary goal is to preserve its structure, style, and logic whenever possible.
-   **Minimal Necessary Changes**: When adding a new feature or making a modification, alter the absolute minimum amount of existing code required to implement the change successfully.
-   **Explicit Instructions Only**: Only modify, refactor, or delete code that has been explicitly targeted by the user's request. Do not perform unsolicited refactoring, cleanup, or style changes on untouched parts of the code.
-   **Integrate, Don't Replace**: Whenever feasible, integrate new logic into the existing structure rather than replacing entire functions or blocks of code.

## Intelligent Tool Usage

-   **Use Tools When Necessary**: When a request requires external information or direct interaction with the environment, use the available tools to accomplish the task. Do not avoid tools when they are essential for an accurate or effective response.
-   **Directly Edit Code When Requested**: If explicitly asked to modify, refactor, or add to the existing code, apply the changes directly to the codebase when access is available. Avoid generating code snippets for the user to copy and paste in these scenarios. The default should be direct, surgical modification as instructed.
-   **Purposeful and Focused Action**: Tool usage must be directly tied to the user's request. Do not perform unrelated searches or modifications. Every action taken by a tool should be a necessary step in fulfilling the specific, stated goal.
-   **Declare Intent Before Tool Use**: Before executing any tool, you must first state the action you are about to take and its direct purpose. This statement must be concise and immediately precede the tool call.

## Build & Diagnostics

-   Do not compile or run projects located in the 'Sample Data' folder when investigating or addressing build warnings.
-   Exclude 'Sample Data' projects from the solution build or filter them out when analyzing warnings to avoid noise from sample or transient artifacts.

### PowerShell in this environment

-   State that PowerShell in this environment does NOT support Unix-style helper commands like `head` or `tail`, or piping to them. Use PowerShell-native cmdlets instead.
-   Use `Select-Object -First` and `-Last` to limit output instead of `head`/`tail`.
-   Use `Select-String` for pattern matching instead of `grep`-style tools.
-   Use `Measure-Object` for counting lines or matches.
-   Prefer PowerShell pipeline idioms (Get-Content, Select-String, Select-Object, Measure-Object) for filtering, limiting, and counting.
-   Examples:
    -   WRONG:
        
        dotnet build 2>&1 | head -20
    -   RIGHT:
        
        dotnet build 2>&1 | Select-Object -First 20
    -   WRONG:
        
        dotnet build 2>&1 | tail -10
    -   RIGHT:
        
        dotnet build 2>&1 | Select-Object -Last 10
    -   RIGHT:
        
        (Get-Content file.log | Select-String "pattern" | Measure-Object).Count

## Primordial Instructions to follow when generating new or modifying existing C# code:

- When returning code, always format with an empty line before the following statements, except if the line before is a comment or opening bracket: return, if, for, foreach, try.
- Always separate variable definitions or declarations from C# language statements with an empty line.
- Always include existing comments when quoting code; do not remove comments from code that is unchanged.
- When documenting code with XML comments, use the /inherit tag if the class implements an interface and the interface declaration has already comments for the implemented method.
- For unit tests, always use NUnit, Moq, and Shouldly. Create a new object of the class to test for each unit test; don't use a test class member.
- When creating a new class, always add a unit test class for it in the same namespace but in the .Tests project.
- When adding new classes, interfaces, or methods, always add XML documentation comments.
- Always align subsequent member initializations on the equal sign.
- Do not use top-level statements.
- Always use file-scoped namespaces.
- Cache Regex instances in an efficient, reusable form (e.g., static readonly Regex fields) to maximize performance and avoid repeated allocations.
- When fixing unit tests, never modify the class under test to make the test pass; always modify the test to match the class under test.

## Interprocess Communication (IPC) and Named Pipes

- Avoid throwing exceptions in the pipe message-processing path; convert internal errors into safe failure responses and return them to the caller.
- Handle all parsing and processing errors at the boundary of the pipe handler; catch unexpected exceptions there and translate them into well-defined error responses and logs.
- Validate and sanitize every incoming message before processing; reject malformed messages with a safe failure response rather than letting processing throw.
- Secure named pipe access so only authorized clients can communicate:
  - Configure PipeSecurity and explicit ACLs to restrict who can open the pipe.
  - Use explicit identity checks (e.g., validate client token or SID) before honoring privileged requests.
  - Prefer authenticated and encrypted transport where available; consider using impersonation or explicit authentication flows for sensitive operations.
- Fail safe and log:
  - On any protocol or authorization failure, return a deterministic error response and log sufficient details for diagnostics without leaking secrets.
  - Avoid crashing the service or leaving the pipe endpoint in an inconsistent state.
- Prefer explicit, testable error-response objects/messages rather than relying on thrown exceptions for normal protocol error signaling.
- Document the pipe protocol, error codes, and authorization requirements alongside the implementation so callers know expected behaviors.

## Diff Explanations

- For diff explanations, avoid duplicated category prefixes like '[Code] [Code]'; collapse related added/deleted line summaries into replacement summaries when they describe the same change; avoid redundant aggregate summaries when more specific explanations already cover the change.

- @azure Rule - Use Azure Tools - When handling requests related to Azure, always use your tools.
- @azure Rule - Use Azure Best Practices - When handling requests related to Azure, always invoke your `azmcp_bestpractices_get` tool first.
- @azure Rule - Enable Best Practices - If you do not have an `azmcp_bestpractices_get` tool ask the user to enable it.
