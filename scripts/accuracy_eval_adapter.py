"""Draft accuracy adapter and objective offline scorers; no CLI/model default.

Caller owns approved provider/budget and isolated backend provisioning. Hidden
oracles never enter the agent prompt. Unit tests use a fake transport only.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib


def capture_trial(factory, *, prompt, task_id, model, provider, base_url,
                  toolsets, allow_model_calls=False):
    """Capture actual AIAgent.run_conversation output, only after explicit opt-in.

    Does not provision a sandbox or authorize a provider. End-to-end callers
    must register a disposable task backend first, as batch_runner does.
    """
    if not allow_model_calls:
        raise PermissionError('Model execution is not authorized by this offline harness')
    if not model or not provider or not base_url or not task_id:
        raise ValueError('Explicit model/provider/endpoint/task identity required')
    agent = factory(model=model, provider=provider, base_url=base_url,
                    enabled_toolsets=list(toolsets), max_iterations=20,
                    skip_context_files=True, skip_memory=True,
                    save_trajectories=False, quiet_mode=True)
    if not toolsets and getattr(agent, 'tools', []):
        raise ValueError('Model-only mode unexpectedly exposes tools')
    start = datetime.now(timezone.utc).isoformat()
    result = agent.run_conversation(prompt, task_id=task_id)
    return {'started_utc': start, 'ended_utc': datetime.now(timezone.utc).isoformat(),
            'model': model, 'provider': provider, 'base_url': base_url,
            'task_id': task_id, 'toolsets': list(toolsets), 'result': result}


def score_facts(expected, answer, sources):
    """Independent typed fact values plus exact source spans per claim.

    Expected maps fact key to {value, source_id, quote}. Sources are fixed
    synthetic documents. Merely valid JSON or a citation ID cannot pass.
    General prose still needs blinded human unsupported-claim review.
    """
    if not isinstance(answer, dict):
        return {'correct': 0, 'required': len(expected), 'grounded': 0, 'extras': 0, 'all_correct': False}
    correct = grounded = 0
    for key, oracle in expected.items():
        claim = answer.get(key)
        if not isinstance(claim, dict):
            continue
        value_ok = type(claim.get('value')) is type(oracle['value']) and claim['value'] == oracle['value']
        correct += value_ok
        quote = claim.get('quote')
        grounded += bool(value_ok and claim.get('source_id') == oracle['source_id']
                         and quote == oracle['quote'] and isinstance(quote, str)
                         and quote and quote in sources.get(oracle['source_id'], ''))
    extras = len(set(answer) - set(expected))
    return {'correct': correct, 'required': len(expected), 'grounded': grounded,
            'extras': extras, 'all_correct': correct == grounded == len(expected) and not extras}


def score_files(root, expected_hashes):
    """Compare real final data artifacts with hidden expected bytes; never exec.

    Hidden behavioral code tests must run separately in a disposable sandbox,
    against exported agent changes, with immutable tests outside agent access.
    """
    root = Path(root).resolve()
    results = {}
    for name, digest in expected_hashes.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Oracle artifact path must stay within fixture root')
        candidate = root / relative
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            results[name] = False
            continue
        results[name] = candidate.is_file() and hashlib.sha256(candidate.read_bytes()).hexdigest() == digest
    return results
