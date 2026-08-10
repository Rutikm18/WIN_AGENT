FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace \
    PROGRAMDATA=/tmp/programdata

WORKDIR /workspace
COPY agent /workspace/agent

ENTRYPOINT ["python", "/workspace/agent/os/windows/advanced_support/scenario_runner.py"]
CMD ["--all"]
