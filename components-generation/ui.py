import asyncio
import os
import json
from pathlib import Path

import questionary
from rich.markdown import Markdown
from rich.panel import Panel

from console import console


def ask_before_step(step_name: str, *, has_previous: bool, timeout_s: float = 60.0) -> str:
    """Ask what to do BEFORE starting a step.

    Returns one of: 'continue', 'retry_prev', 'skip', 'exit'.
    Defaults to 'continue' after timeout.
    """
    if os.environ.get("GENERATION_NONINTERACTIVE") == "1":
        return "continue"
    console.print()
    console.print(
        f"[blue italic]About to start: {step_name} (auto-continue in {timeout_s:.0f}s)[/blue italic]"
    )

    choices = [
        "Continue",
        questionary.Choice(
            "Retry previous step", disabled=None if has_previous else "No previous step"
        ),
        "Skip the step",
        "Exit",
    ]

    question = questionary.select(
        "Choose an action:",
        choices=choices,
        style=questionary.Style(
            [
                ("qmark", "fg:#673ab7 bold"),
                ("question", "bold"),
                ("answer", "fg:#f44336 bold"),
                ("pointer", "fg:#673ab7 bold"),
                ("highlighted", "fg:#673ab7 bold"),
                ("selected", "fg:#cc5454"),
                ("separator", "fg:#cc5454"),
                ("instruction", ""),
                ("text", ""),
                ("disabled", "fg:#858585 italic"),
            ]
        ),
    )

    async def get_input_with_timeout():
        try:
            return await asyncio.wait_for(question.ask_async(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return "TIMEOUT"

    choice = asyncio.run(get_input_with_timeout())
    if choice == "TIMEOUT" or choice is None:
        console.print("[dim]Timeout reached. Defaulting to: Continue[/dim]")
        choice = "Continue"

    if choice == "Continue":
        return "continue"
    if choice == "Retry previous step":
        return "retry_prev"
    if choice == "Skip the step":
        return "skip"
    return "exit"


def run_agent_step(*, agent_graph, prompt_text: str, config, step_title: str):
    """Run the agent with a loading spinner and formatted output."""

    console.rule(f"[bold blue]{step_title}[/bold blue]")

    with console.status(
        f"[bold green]LLM is thinking & coding for {step_title}...[/bold green]",
        spinner="dots",
    ):
        response = agent_graph.invoke(
            {"messages": [{"role": "user", "content": prompt_text}]},
            config=config,
        )
        final_response = response["messages"][-1].content

    if os.environ.get("GENERATION_LOG_DIR"):
        folder = Path(os.environ["GENERATION_LOG_DIR"])
        folder.mkdir(parents=True, exist_ok=True)
        name = "".join(c if c.isalnum() else "_" for c in step_title)
        (folder / (name + ".json")).write_text(json.dumps(
            [m.model_dump(mode="json") for m in response["messages"]],
            ensure_ascii=False, indent=2))

    console.print(
        Panel(
            Markdown(final_response),
            title=f"Result: {step_title}",
            border_style="blue",
            expand=False,
        )
    )

    return response
