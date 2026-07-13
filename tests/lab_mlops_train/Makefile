# Lab 7: MLOps QLoRA Training Smoke
# Requires: NVIDIA GPU (8GB+ VRAM) or Apple MPS

install:
	pip install -r tests/lab_mlops_train/requirements.txt

# Standard GPU run
test:
	pytest tests/lab_mlops_train/test_qlora_smoke.py -v

# CPU-only (slow -- for logic verification without GPU)
test-cpu:
	NEXUS_TEST_FORCE_CPU=1 pytest tests/lab_mlops_train/test_qlora_smoke.py -v

# Single class group
test-projector:
	pytest tests/lab_mlops_train/test_qlora_smoke.py -v -k "TestSpatialProjector"

test-gradient:
	pytest tests/lab_mlops_train/test_qlora_smoke.py -v -k "TestGradientFlow"

test-adapter:
	pytest tests/lab_mlops_train/test_qlora_smoke.py -v -k "TestLoraAdapter"

.PHONY: install test test-cpu test-projector test-gradient test-adapter
