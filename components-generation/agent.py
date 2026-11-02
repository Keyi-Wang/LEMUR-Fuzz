import os
from pathlib import Path

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver

from tools import append_and_verify_code, make_rfc_search, read_file, save_and_verify_code


def build_agent_graph(*, retriever):
    model = os.environ.get("GENERATION_MODEL", "gpt-5.2")
    options = {"model": model, "timeout": 180, "max_retries": 2}
    if model.startswith("gpt-5"):
        options.update(reasoning_effort="low", max_completion_tokens=24000)
    else:
        options.update(temperature=0)
    llm = ChatOpenAI(**options)
    rfc_search = make_rfc_search(retriever)

    tools = [rfc_search, save_and_verify_code,
             read_file, append_and_verify_code]

    memory = MemorySaver()

    return create_agent(
        model=llm,
        tools=tools,
        checkpointer=memory,
        system_prompt="""
        You are a helpful assistant expert in C programming and protocol fuzzing.
        """ + (Path(os.environ["GENERATION_CONTEXT"]).read_text()
               if os.environ.get("GENERATION_CONTEXT") else ""),
    )
