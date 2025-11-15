# Attacker Challenge
<!-- vscode-markdown-toc -->
* [Overview](#overview)
    * [Challenge Dates](#challenge-dates)
    * [Rules / Terms](#rules-/-terms)
    * [Requirements](#requirements)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->


## <a name='overview'></a>Overview

### <a name='challenge-dates'></a>Challenge Dates
Aug 6 - Sep 18, 2020 (AoE)

### <a name='rules-/-terms'></a>Rules / Terms
[https://mlsec.io/tos](https://mlsec.io/tos)


## Model1 Attack Toolkit
The `model1` folder collects the five Colab methods from the original `attack2.py`
notebook and turns each into a standalone pipeline that can be executed locally.
Every script performs the same high-level steps: import the encrypted dataset
archive, unzip/extract into an isolated workspace, run the corresponding attack
logic, emit `compare_report.csv` + `sha256sums.txt`, and finally compress the
results back into a zip bundle for sharing.

- `method1_dropper.py` - Cross-compiled dropper that XOR/Base64 encrypts each
  payload, generates a Windows stub with MinGW, and falls back to copying if
  compilation fails.
- `method2_hybrid_overlay.py` - Hybrid overlay/dropper/PE-mod pipeline that
  mixes large benign padding, compiled droppers, and header tweaks per file
  index.
- `method3_safe_overlay.py` - Safe overlay-only strategies that strictly modify
  non-executable regions (plain overlay, timestamp+overlay, aggressive overlay)
  to maintain behavioral equivalence.
- `method4_agent.py` - Advanced agent that chains timestamp tweaks, benign
  padding, UPX, AES crypter, and dropper tools with capa validation and HTTP
  model scoring.
- `method5_llm_agent.py` - LLM-guided agent that leverages the Gemini API for
  scoring and keeps iterating through the same transformation toolbox until the
  LLM score falls below the configured target.

> Place your `to_be_evaded_ds.zip` archive under `attacker/` (or pass
> `--archive` to any script) before invoking a method.
