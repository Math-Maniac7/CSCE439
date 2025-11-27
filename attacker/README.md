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
The `model1` folder contains 5 optimized attack methods that combine the best
techniques from previous implementations. Every script performs the same
high-level steps: import the encrypted dataset archive, unzip/extract into an
isolated workspace, run the corresponding attack logic, emit `compare_report.csv`
+ `sha256sums.txt`, and finally compress the results back into a zip bundle for
sharing.

- `methodA_dropper_metadata_overlay.py` - **Combined method**: Dropper (XOR+Base64
  encrypted payload in C++ stub) + Metadata mutation (TimeDateStamp randomization,
  CheckSum=0) + Low-entropy overlay (~1MB). Loader writes to %TEMP% and executes
  via CreateProcess. Includes benign features (Windows version strings, dead code
  paths, registry lookups).

- `methodB_section_rename_overlay.py` - Section renaming (.text→.code, .data→.info)
  + Benign overlay with section-like patterns. Preserves all imports and functionality.

- `methodC_import_obfuscation.py` - Import table obfuscation + Padding. Adds benign
  import strings, modifies import metadata, adds large padding with import-like patterns.

- `methodD_resource_manipulation.py` - Resource table manipulation + Overlay.
  Modifies resource entries, adds fake resources with benign data, appends overlay
  with resource-like patterns.

- `methodE_multilayer_padding.py` - Multi-layer padding with entropy balancing.
  Applies multiple layers with different patterns, balances entropy (mix high/low),
  creates complex byte distribution patterns.

> Place your `to_be_evaded_ds.zip` archive under `attacker/` (or pass
> `--archive` to any script) before invoking a method.
