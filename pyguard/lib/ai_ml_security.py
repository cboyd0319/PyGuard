"""
AI/ML Security Analysis.

Detects security vulnerabilities in AI/ML applications including prompt injection,
model serialization risks, training data poisoning, and GPU memory leakage.

Security Areas Covered:
- Prompt injection in LLM applications
- System prompt override attempts (delimiter injection) - AIML011
- Unicode/homoglyph injection (zero-width characters, bi-directional overrides) - AIML012
- Role confusion attacks (DAN mode, jailbreaks) - AIML013
- Instruction concatenation bypasses - AIML014
- Multi-language prompt injection (non-English) - AIML015
- Markdown injection in prompts - AIML016
- XML/JSON payload injection - AIML017
- SQL-style comment injection - AIML018
- Escape sequence injection - AIML019
- Token stuffing attacks (context window exhaustion) - AIML020
- Recursive prompt injection (prompts containing prompts) - AIML021
- Base64 encoded injection attempts - AIML022
- ROT13/Caesar cipher obfuscation - AIML023
- Invisible character injection (zero-width spaces) - AIML024
- Right-to-left override attacks (Unicode bidi) - AIML025
- Prompt template literal injection - AIML026
- F-string injection in prompts - AIML027
- Variable substitution attacks - AIML028
- Context window overflow - AIML029
- Attention mechanism manipulation - AIML030
- URL-based injection (fetched web content) - AIML031
- Document poisoning (PDF, DOCX injection) - AIML032
- Image-based prompt injection (OCR manipulation) - AIML033
- API response injection (3rd party data) - AIML034
- Database content injection - AIML035
- File upload injection vectors - AIML036
- Email content injection - AIML037
- Social media scraping injection - AIML038
- RAG poisoning (retrieval augmented generation) - AIML039
- Vector database injection - AIML040
- Knowledge base tampering - AIML041
- Citation manipulation - AIML042
- Search result poisoning - AIML043
- User profile injection - AIML044
- Conversation history injection - AIML045
- Missing rate limiting on LLM API calls - AIML046
- Unvalidated temperature/top_p parameters - AIML047
- Max_tokens manipulation (DoS) - AIML048
- Streaming response injection - AIML049
- Function calling injection - AIML050
- Tool use parameter tampering - AIML051
- System message manipulation via API - AIML052
- Model selection bypass - AIML053
- API key exposure in client code - AIML054
- Hardcoded model names (version lock-in) - AIML055
- Missing timeout configurations - AIML056
- Unhandled API errors (info disclosure) - AIML057
- Token counting bypass - AIML058
- Cost overflow attacks - AIML059
- Multi-turn conversation state injection - AIML060
- Missing output sanitization - AIML061
- Code execution in LLM responses - AIML062
- SQL injection via generated queries - AIML063
- XSS via generated HTML - AIML064
- Command injection via generated shell scripts - AIML065
- Path traversal in generated file paths - AIML066
- Arbitrary file access via generated code - AIML067
- Sensitive data leakage in responses - AIML068
- PII disclosure from training data - AIML069
- Copyright violation risks (memorized content) - AIML070
- torch.load() without weights_only=True - AIML071
- Unsafe pickle in torch.save/load - AIML072
- Missing model integrity verification - AIML073
- Untrusted model URL loading - AIML074
- Model poisoning in state_dict - AIML075
- Custom layer/module injection - AIML076
- Unsafe torch.jit.load() - AIML077
- TorchScript deserialization risks - AIML078
- ONNX model tampering - AIML079
- Model metadata injection - AIML080
- Missing GPU memory limits - AIML081
- Tensor size attacks (memory exhaustion) - AIML082
- Quantization vulnerabilities - AIML083
- Mixed precision attacks - AIML084
- Model zoo trust verification - AIML085
- SavedModel arbitrary code execution - AIML086
- HDF5 deserialization attacks - AIML087
- Custom object injection in model.load - AIML088
- TensorFlow Hub model trust - AIML089
- Graph execution injection - AIML090
- Checkpoint poisoning - AIML091
- Keras Lambda layer code injection - AIML092
- Custom metric/loss function tampering - AIML093
- TF Lite model manipulation - AIML094
- TensorBoard log injection - AIML095
- Model serving vulnerabilities (TF Serving) - AIML096
- GraphDef manipulation - AIML097
- Operation injection attacks - AIML098
- Resource exhaustion via model architecture - AIML099
- TFRecord poisoning - AIML100
- from_pretrained() trust issues - AIML101
- Model card credential leakage - AIML102
- Tokenizer vulnerabilities - AIML103
- Pipeline injection attacks - AIML104
- Dataset poisoning (Hugging Face Datasets) - AIML105
- Missing model signature verification - AIML106
- Arbitrary file loading in model config - AIML107
- Space app injection (Gradio/Streamlit) - AIML108
- Model repository tampering - AIML109
- Private model access control - AIML110
- Unvalidated training data sources - AIML111
- Missing data sanitization - AIML112
- PII leakage in training datasets - AIML113
- Copyright-infringing data inclusion - AIML114
- Data poisoning detection (label flipping) - AIML115
- Backdoor injection in datasets - AIML116
- Trigger pattern insertion - AIML117
- Data augmentation attacks - AIML118
- Synthetic data vulnerabilities - AIML119
- Web scraping data risks - AIML120
- User-generated content risks - AIML121
- Missing data provenance tracking - AIML122
- Gradient manipulation attacks - AIML123
- Learning rate manipulation - AIML124
- Optimizer state poisoning - AIML125
- Checkpoint tampering during training - AIML126
- Early stopping bypass - AIML127
- Validation set poisoning - AIML128
- TensorBoard logging injection - AIML129
- Experiment tracking manipulation - AIML130
- Distributed training node compromise - AIML131
- Parameter server vulnerabilities - AIML132
- Base model poisoning - AIML133
- Fine-tuning data injection - AIML134
- Catastrophic forgetting exploitation - AIML135
- PEFT attacks - AIML136
- LoRA poisoning - AIML137
- Adapter injection - AIML138
- Prompt tuning manipulation - AIML139
- Instruction fine-tuning risks - AIML140
- Missing input adversarial defense - AIML141
- No FGSM protection - AIML142
- PGD vulnerability - AIML143
- C&W attack surface - AIML144
- DeepFool susceptibility - AIML145
- Universal adversarial perturbations - AIML146
- Black-box attack vulnerability - AIML147
- Transfer attack risks - AIML148
- Physical adversarial examples - AIML149
- Adversarial patch detection missing - AIML150
- Missing adversarial training - AIML151
- No certified defenses - AIML152
- Input gradient masking - AIML153
- Defensive distillation gaps - AIML154
- Ensemble defenses missing - AIML155
- Randomization defense gaps - AIML156
- Input transformation missing - AIML157
- Detection mechanism missing - AIML158
- Rejection option missing - AIML159
- Robustness testing absent - AIML160
- Model inversion attack vectors
- Adversarial input acceptance
- Model extraction vulnerabilities
- AI bias detection in code
- Insecure model serialization (PyTorch, TensorFlow)
- Missing input validation for ML models
- GPU memory leakage
- Federated learning privacy risks

Total Security Checks: 160 (v0.7.0 - AI/ML Security Dominance Plan Phase 1 Complete - Milestone 1)

References:
- OWASP LLM Top 10 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Critical
- NIST AI Risk Management | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf | High
- CWE-94 (Code Injection) | https://cwe.mitre.org/data/definitions/94.html | Critical
- CWE-502 (Deserialization of Untrusted Data) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
- CWE-327 (Broken Cryptographic Algorithm) | https://cwe.mitre.org/data/definitions/327.html | High
"""

import ast
import re
from pathlib import Path
from typing import List, Set

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class AIMLSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting AI/ML security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_llm_framework = False
        self.has_ml_framework = False
        self.has_pytorch = False
        self.has_tensorflow = False
        self.has_transformers = False
        self.model_loads: Set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track AI/ML framework imports."""
        if node.module:
            # LLM frameworks
            if any(x in node.module for x in ["openai", "langchain", "llama", "anthropic"]):
                self.has_llm_framework = True
            # ML frameworks
            elif "torch" in node.module or "pytorch" in node.module:
                self.has_pytorch = True
            elif "tensorflow" in node.module or "tf" in node.module:
                self.has_tensorflow = True
            elif "transformers" in node.module or "huggingface" in node.module:
                self.has_transformers = True
            elif any(x in node.module for x in ["sklearn", "keras", "jax"]):
                self.has_ml_framework = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track AI/ML framework imports (import statements)."""
        for alias in node.names:
            if any(x in alias.name for x in ["openai", "langchain", "llama", "anthropic"]):
                self.has_llm_framework = True
            elif "torch" in alias.name or "pytorch" in alias.name:
                self.has_pytorch = True
            elif "tensorflow" in alias.name:
                self.has_tensorflow = True
            elif "transformers" in alias.name:
                self.has_transformers = True
            elif any(x in alias.name for x in ["sklearn", "keras", "jax"]):
                self.has_ml_framework = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for AI/ML security vulnerabilities in function calls."""
        # AIML001: Prompt injection
        self._check_prompt_injection(node)
        
        # AIML011: System prompt override (delimiter injection)
        self._check_system_prompt_override(node)
        
        # AIML012: Unicode/homoglyph injection
        self._check_unicode_injection(node)
        
        # AIML013: Role confusion attacks (DAN mode)
        self._check_role_confusion(node)
        
        # AIML014: Instruction concatenation bypasses
        self._check_instruction_concatenation(node)
        
        # AIML015: Multi-language prompt injection
        self._check_multilanguage_injection(node)
        
        # AIML016: Markdown injection in prompts
        self._check_markdown_injection(node)
        
        # AIML017: XML/JSON payload injection
        self._check_payload_injection(node)
        
        # AIML018: SQL-style comment injection
        self._check_sql_comment_injection(node)
        
        # AIML019: Escape sequence injection
        self._check_escape_sequence_injection(node)
        
        # AIML020: Token stuffing attacks
        self._check_token_stuffing(node)
        
        # AIML021: Recursive prompt injection
        self._check_recursive_prompt_injection(node)
        
        # AIML022: Base64 encoded injection
        self._check_base64_injection(node)
        
        # AIML023: ROT13/Caesar cipher obfuscation
        self._check_rot13_obfuscation(node)
        
        # AIML024: Invisible character injection (zero-width spaces)
        self._check_invisible_char_injection(node)
        
        # AIML025: Right-to-left override attacks (Unicode bidi)
        self._check_bidi_override(node)
        
        # AIML026: Prompt template literal injection
        self._check_template_literal_injection(node)
        
        # AIML027: F-string injection in prompts
        self._check_fstring_injection(node)
        
        # AIML028: Variable substitution attacks
        self._check_variable_substitution(node)
        
        # AIML029: Context window overflow
        self._check_context_window_overflow(node)
        
        # AIML030: Attention mechanism manipulation
        self._check_attention_manipulation(node)
        
        # AIML031: URL-based injection (fetched web content)
        self._check_url_based_injection(node)
        
        # AIML032: Document poisoning (PDF, DOCX injection)
        self._check_document_poisoning(node)
        
        # AIML033: Image-based prompt injection (OCR manipulation)
        self._check_image_injection(node)
        
        # AIML034: API response injection (3rd party data)
        self._check_api_response_injection(node)
        
        # AIML035: Database content injection
        self._check_database_injection(node)
        
        # AIML036: File upload injection vectors
        self._check_file_upload_injection(node)
        
        # AIML037: Email content injection
        self._check_email_injection(node)
        
        # AIML038: Social media scraping injection
        self._check_social_scraping_injection(node)
        
        # AIML039: RAG poisoning (retrieval augmented generation)
        self._check_rag_poisoning(node)
        
        # AIML040: Vector database injection
        self._check_vector_db_injection(node)
        
        # AIML041: Knowledge base tampering
        self._check_knowledge_base_tampering(node)
        
        # AIML042: Citation manipulation
        self._check_citation_manipulation(node)
        
        # AIML043: Search result poisoning
        self._check_search_poisoning(node)
        
        # AIML044: User profile injection
        self._check_user_profile_injection(node)
        
        # AIML045: Conversation history injection
        self._check_conversation_history_injection(node)
        
        # Phase 1.1.3: LLM API Security (15 checks)
        # AIML046: Missing rate limiting on LLM API calls
        self._check_missing_rate_limiting(node)
        
        # AIML047: Unvalidated temperature/top_p parameters
        self._check_unvalidated_llm_parameters(node)
        
        # AIML048: Max_tokens manipulation (DoS)
        self._check_max_tokens_manipulation(node)
        
        # AIML049: Streaming response injection
        self._check_streaming_response_injection(node)
        
        # AIML050: Function calling injection
        self._check_function_calling_injection(node)
        
        # AIML051: Tool use parameter tampering
        self._check_tool_use_tampering(node)
        
        # AIML052: System message manipulation via API
        self._check_system_message_manipulation(node)
        
        # AIML053: Model selection bypass
        self._check_model_selection_bypass(node)
        
        # AIML054: API key exposure in client code
        self._check_api_key_exposure(node)
        
        # AIML055: Hardcoded model names (version lock-in)
        self._check_hardcoded_model_names(node)
        
        # AIML056: Missing timeout configurations
        self._check_missing_timeout(node)
        
        # AIML057: Unhandled API errors (info disclosure)
        self._check_unhandled_api_errors(node)
        
        # AIML058: Token counting bypass
        self._check_token_counting_bypass(node)
        
        # AIML059: Cost overflow attacks
        self._check_cost_overflow(node)
        
        # AIML060: Multi-turn conversation state injection
        self._check_conversation_state_injection(node)
        
        # Phase 1.1.4: Output Validation & Filtering (10 checks)
        # AIML061: Missing output sanitization
        self._check_missing_output_sanitization(node)
        
        # AIML062: Code execution in LLM responses
        self._check_code_execution_in_response(node)
        
        # AIML063: SQL injection via generated queries
        self._check_sql_injection_in_generated(node)
        
        # AIML064: XSS via generated HTML
        self._check_xss_in_generated_html(node)
        
        # AIML065: Command injection via generated shell scripts
        self._check_command_injection_in_generated(node)
        
        # AIML066: Path traversal in generated file paths
        self._check_path_traversal_in_generated(node)
        
        # AIML067: Arbitrary file access via generated code
        self._check_arbitrary_file_access_in_generated(node)
        
        # AIML068: Sensitive data leakage in responses
        self._check_sensitive_data_leakage(node)
        
        # AIML069: PII disclosure from training data
        self._check_pii_disclosure(node)
        
        # AIML070: Copyright violation risks (memorized content)
        self._check_copyright_violation_risk(node)
        
        # Phase 1.2: Model Serialization & Loading (40 checks)
        # Phase 1.2.1: PyTorch Model Security (15 checks - AIML071-AIML085)
        # AIML071: torch.load() without weights_only=True
        self._check_torch_load_unsafe(node)
        
        # AIML072: Unsafe pickle in torch.save/load
        self._check_torch_pickle_unsafe(node)
        
        # AIML073: Missing model integrity verification
        self._check_missing_model_integrity(node)
        
        # AIML074: Untrusted model URL loading
        self._check_untrusted_model_url(node)
        
        # AIML075: Model poisoning in state_dict
        self._check_state_dict_poisoning(node)
        
        # AIML076: Custom layer/module injection
        self._check_custom_module_injection(node)
        
        # AIML077: Unsafe torch.jit.load()
        self._check_torch_jit_unsafe(node)
        
        # AIML078: TorchScript deserialization risks
        self._check_torchscript_deserialization(node)
        
        # AIML079: ONNX model tampering
        self._check_onnx_tampering(node)
        
        # AIML080: Model metadata injection
        self._check_model_metadata_injection(node)
        
        # AIML081: Missing GPU memory limits
        self._check_missing_gpu_limits(node)
        
        # AIML082: Tensor size attacks
        self._check_tensor_size_attacks(node)
        
        # AIML083: Quantization vulnerabilities
        self._check_quantization_vulnerabilities(node)
        
        # AIML084: Mixed precision attacks
        self._check_mixed_precision_attacks(node)
        
        # AIML085: Model zoo trust verification
        self._check_model_zoo_trust(node)
        
        # Phase 1.2.2: TensorFlow/Keras Security (15 checks - AIML086-AIML100)
        # AIML086: SavedModel arbitrary code execution
        self._check_savedmodel_unsafe(node)
        
        # AIML087: HDF5 deserialization attacks
        self._check_hdf5_deserialization(node)
        
        # AIML088: Custom object injection in model.load
        self._check_keras_custom_object_injection(node)
        
        # AIML089: TensorFlow Hub model trust
        self._check_tf_hub_trust(node)
        
        # AIML090: Graph execution injection
        self._check_graph_execution_injection(node)
        
        # AIML091: Checkpoint poisoning
        self._check_checkpoint_poisoning(node)
        
        # AIML092: Keras Lambda layer code injection
        self._check_keras_lambda_injection(node)
        
        # AIML093: Custom metric/loss function tampering
        self._check_custom_metric_tampering(node)
        
        # AIML094: TF Lite model manipulation
        self._check_tflite_manipulation(node)
        
        # AIML095: TensorBoard log injection
        self._check_tensorboard_injection(node)
        
        # AIML096: Model serving vulnerabilities (TF Serving)
        self._check_tf_serving_vulnerabilities(node)
        
        # AIML097: GraphDef manipulation
        self._check_graphdef_manipulation(node)
        
        # AIML098: Operation injection attacks
        self._check_operation_injection(node)
        
        # AIML099: Resource exhaustion via model architecture
        self._check_resource_exhaustion_model(node)
        
        # AIML100: TFRecord poisoning
        self._check_tfrecord_poisoning(node)
        
        # Phase 1.2.3: Hugging Face & Transformers (10 checks - AIML101-AIML110)
        # AIML101: from_pretrained() trust issues
        self._check_from_pretrained_trust(node)
        
        # AIML102: Model card credential leakage
        self._check_model_card_credentials(node)
        
        # AIML103: Tokenizer vulnerabilities
        self._check_tokenizer_vulnerabilities(node)
        
        # AIML104: Pipeline injection attacks
        self._check_pipeline_injection(node)
        
        # AIML105: Dataset poisoning (Hugging Face Datasets)
        self._check_hf_dataset_poisoning(node)
        
        # AIML106: Missing model signature verification
        self._check_missing_model_signature(node)
        
        # AIML107: Arbitrary file loading in model config
        self._check_arbitrary_file_in_config(node)
        
        # AIML108: Space app injection (Gradio/Streamlit)
        self._check_space_app_injection(node)
        
        # AIML109: Model repository tampering
        self._check_model_repo_tampering(node)
        
        # AIML110: Private model access control
        self._check_private_model_access(node)
        
        # Phase 1.3: Training & Fine-Tuning Security (30 checks)
        # Phase 1.3.1: Training Data Security (12 checks - AIML111-AIML122)
        # AIML111: Unvalidated training data sources
        self._check_unvalidated_training_data(node)
        
        # AIML112: Missing data sanitization
        self._check_missing_data_sanitization(node)
        
        # AIML113: PII leakage in training datasets
        self._check_pii_in_training_data(node)
        
        # AIML114: Copyright-infringing data inclusion
        self._check_copyright_infringing_data(node)
        
        # AIML115: Data poisoning detection (label flipping)
        self._check_label_flipping_detection(node)
        
        # AIML116: Backdoor injection in datasets
        self._check_backdoor_in_dataset(node)
        
        # AIML117: Trigger pattern insertion
        self._check_trigger_pattern_insertion(node)
        
        # AIML118: Data augmentation attacks
        self._check_data_augmentation_attacks(node)
        
        # AIML119: Synthetic data vulnerabilities
        self._check_synthetic_data_vulnerabilities(node)
        
        # AIML120: Web scraping data risks
        self._check_web_scraping_data_risks(node)
        
        # AIML121: User-generated content risks
        self._check_user_generated_content_risks(node)
        
        # AIML122: Missing data provenance tracking
        self._check_missing_data_provenance(node)
        
        # Phase 1.3.2: Training Process Security (10 checks - AIML123-AIML132)
        # AIML123: Gradient manipulation attacks
        self._check_gradient_manipulation(node)
        
        # AIML124: Learning rate manipulation
        self._check_learning_rate_manipulation(node)
        
        # AIML125: Optimizer state poisoning
        self._check_optimizer_state_poisoning(node)
        
        # AIML126: Checkpoint tampering during training
        self._check_checkpoint_tampering_training(node)
        
        # AIML127: Early stopping bypass
        self._check_early_stopping_bypass(node)
        
        # AIML128: Validation set poisoning
        self._check_validation_set_poisoning(node)
        
        # AIML129: TensorBoard logging injection
        self._check_tensorboard_logging_injection(node)
        
        # AIML130: Experiment tracking manipulation
        self._check_experiment_tracking_manipulation(node)
        
        # AIML131: Distributed training node compromise
        self._check_distributed_training_node_compromise(node)
        
        # AIML132: Parameter server vulnerabilities
        self._check_parameter_server_vulnerabilities(node)
        
        # Phase 1.3.3: Fine-Tuning Risks (8 checks - AIML133-AIML140)
        # AIML133: Base model poisoning
        self._check_base_model_poisoning(node)
        
        # AIML134: Fine-tuning data injection
        self._check_fine_tuning_data_injection(node)
        
        # AIML135: Catastrophic forgetting exploitation
        self._check_catastrophic_forgetting_exploitation(node)
        
        # AIML136: PEFT attacks
        self._check_peft_attacks(node)
        
        # AIML137: LoRA poisoning
        self._check_lora_poisoning(node)
        
        # AIML138: Adapter injection
        self._check_adapter_injection(node)
        
        # AIML139: Prompt tuning manipulation
        self._check_prompt_tuning_manipulation(node)
        
        # AIML140: Instruction fine-tuning risks
        self._check_instruction_fine_tuning_risks(node)
        
        # Phase 1.4: Adversarial ML & Model Robustness (20 checks)
        # Phase 1.4.1: Adversarial Input Detection (10 checks - AIML141-AIML150)
        # AIML141: Missing input adversarial defense
        self._check_missing_adversarial_defense(node)
        
        # AIML142: No FGSM protection
        self._check_no_fgsm_protection(node)
        
        # AIML143: PGD vulnerability
        self._check_pgd_vulnerability(node)
        
        # AIML144: C&W attack surface
        self._check_cw_attack_surface(node)
        
        # AIML145: DeepFool susceptibility
        self._check_deepfool_susceptibility(node)
        
        # AIML146: Universal adversarial perturbations
        self._check_universal_adversarial_perturbations(node)
        
        # AIML147: Black-box attack vulnerability
        self._check_black_box_attack_vulnerability(node)
        
        # AIML148: Transfer attack risks
        self._check_transfer_attack_risks(node)
        
        # AIML149: Physical adversarial examples
        self._check_physical_adversarial_examples(node)
        
        # AIML150: Adversarial patch detection missing
        self._check_adversarial_patch_detection_missing(node)
        
        # Phase 1.4.2: Model Robustness (10 checks - AIML151-AIML160)
        # AIML151: Missing adversarial training
        self._check_missing_adversarial_training(node)
        
        # AIML152: No certified defenses
        self._check_no_certified_defenses(node)
        
        # AIML153: Input gradient masking
        self._check_input_gradient_masking(node)
        
        # AIML154: Defensive distillation gaps
        self._check_defensive_distillation_gaps(node)
        
        # AIML155: Ensemble defenses missing
        self._check_ensemble_defenses_missing(node)
        
        # AIML156: Randomization defense gaps
        self._check_randomization_defense_gaps(node)
        
        # AIML157: Input transformation missing
        self._check_input_transformation_missing(node)
        
        # AIML158: Detection mechanism missing
        self._check_detection_mechanism_missing(node)
        
        # AIML159: Rejection option missing
        self._check_rejection_option_missing(node)
        
        # AIML160: Robustness testing absent
        self._check_robustness_testing_absent(node)
        
        # Phase 2.1: Feature Engineering & Preprocessing (30 checks)
        # Phase 2.1.1: Data Preprocessing Security (15 checks - AIML161-AIML175)
        # AIML161: Missing input validation in preprocessing
        self._check_missing_preprocessing_validation(node)
        
        # AIML162: Normalization bypass attacks
        self._check_normalization_bypass(node)
        
        # AIML163: Feature scaling manipulation
        self._check_feature_scaling_manipulation(node)
        
        # AIML164: Missing value injection
        self._check_missing_value_injection(node)
        
        # AIML165: Encoding injection
        self._check_encoding_injection(node)
        
        # AIML166: Feature extraction vulnerabilities
        self._check_feature_extraction_vulnerabilities(node)
        
        # AIML167: Dimensionality reduction poisoning
        self._check_dimensionality_reduction_poisoning(node)
        
        # AIML168: Feature selection manipulation
        self._check_feature_selection_manipulation(node)
        
        # AIML169: Missing outlier detection
        self._check_missing_outlier_detection(node)
        
        # AIML170: Data leakage in preprocessing
        self._check_data_leakage_preprocessing(node)
        
        # AIML171: Test/train contamination
        self._check_test_train_contamination(node)
        
        # AIML172: Feature store injection
        self._check_feature_store_injection(node)
        
        # AIML173: Pipeline versioning gaps
        self._check_pipeline_versioning_gaps(node)
        
        # AIML174: Preprocessing state tampering
        self._check_preprocessing_state_tampering(node)
        
        # AIML175: Transformation order vulnerabilities
        self._check_transformation_order_vulnerabilities(node)
        
        # Phase 2.1.2: Feature Store Security (15 checks - AIML176-AIML190)
        # AIML176: Feast feature store injection
        self._check_feast_feature_store_injection(node)
        
        # AIML177: Missing feature validation
        self._check_missing_feature_validation(node)
        
        # AIML178: Feature drift without detection
        self._check_feature_drift_without_detection(node)
        
        # AIML179: Feature serving vulnerabilities
        self._check_feature_serving_vulnerabilities(node)
        
        # AIML180: Offline/online feature skew
        self._check_offline_online_feature_skew(node)
        
        # AIML181: Feature metadata tampering
        self._check_feature_metadata_tampering(node)
        
        # AIML182: Feature lineage missing
        self._check_feature_lineage_missing(node)
        
        # AIML183: Access control gaps
        self._check_feature_access_control_gaps(node)
        
        # AIML184: Feature deletion/corruption
        self._check_feature_deletion_corruption(node)
        
        # AIML185: Version control weaknesses
        self._check_feature_version_control_weaknesses(node)
        
        # AIML186: Feature freshness attacks
        self._check_feature_freshness_attacks(node)
        
        # AIML187: Batch vs real-time inconsistencies
        self._check_batch_realtime_inconsistencies(node)
        
        # AIML188: Feature engineering code injection
        self._check_feature_engineering_code_injection(node)
        
        # AIML189: Schema evolution attacks
        self._check_schema_evolution_attacks(node)
        
        # AIML190: Feature importance manipulation
        self._check_feature_importance_manipulation(node)
        
        # Phase 2.2: Model Training Infrastructure (35 checks)
        # Phase 2.2.1: Distributed Training Security (15 checks - AIML191-AIML205)
        # AIML191: Parameter server vulnerabilities
        self._check_parameter_server_vulnerabilities(node)
        
        # AIML192: Gradient aggregation poisoning
        self._check_gradient_aggregation_poisoning(node)
        
        # AIML193: Byzantine worker attacks
        self._check_byzantine_worker_attacks(node)
        
        # AIML194: All-Reduce manipulation
        self._check_all_reduce_manipulation(node)
        
        # AIML195: Ring-All-Reduce injection
        self._check_ring_all_reduce_injection(node)
        
        # AIML196: Horovod security gaps
        self._check_horovod_security_gaps(node)
        
        # AIML197: DeepSpeed vulnerabilities
        self._check_deepspeed_vulnerabilities(node)
        
        # AIML198: FSDP (Fully Sharded Data Parallel) risks
        self._check_fsdp_risks(node)
        
        # AIML199: ZeRO optimizer state attacks
        self._check_zero_optimizer_state_attacks(node)
        
        # AIML200: Model parallel partition poisoning
        self._check_model_parallel_partition_poisoning(node)
        
        # AIML201: Pipeline parallel injection
        self._check_pipeline_parallel_injection(node)
        
        # AIML202: Tensor parallel tampering
        self._check_tensor_parallel_tampering(node)
        
        # AIML203: Mixed precision training risks
        self._check_mixed_precision_training_risks(node)
        
        # AIML204: Communication backend vulnerabilities
        self._check_communication_backend_vulnerabilities(node)
        
        # AIML205: Collective operation manipulation
        self._check_collective_operation_manipulation(node)
        
        # Phase 2.2.2: GPU & Accelerator Security (10 checks - AIML206-AIML215)
        # AIML206: GPU memory leakage
        self._check_gpu_memory_leakage_aiml206(node)
        
        # AIML207: CUDA kernel injection
        self._check_cuda_kernel_injection(node)
        
        # AIML208: ROCm vulnerabilities
        self._check_rocm_vulnerabilities(node)
        
        # AIML209: TPU security gaps
        self._check_tpu_security_gaps(node)
        
        # AIML210: NPU/IPU risks
        self._check_npu_ipu_risks(node)
        
        # AIML211: Multi-GPU synchronization attacks
        self._check_multi_gpu_synchronization_attacks(node)
        
        # AIML212: Device placement manipulation
        self._check_device_placement_manipulation(node)
        
        # AIML213: CUDA graph poisoning
        self._check_cuda_graph_poisoning(node)
        
        # AIML214: Kernel launch parameter tampering
        self._check_kernel_launch_parameter_tampering(node)
        
        # AIML215: GPU memory exhaustion attacks
        self._check_gpu_memory_exhaustion_attacks(node)
        
        # Phase 2.2.3: Experiment Tracking Security (10 checks - AIML216-AIML225)
        # AIML216: MLflow injection attacks
        self._check_mlflow_injection_attacks(node)
        
        # AIML217: Weights & Biases credential leakage
        self._check_wandb_credential_leakage(node)
        
        # AIML218: Comet.ml experiment tampering
        self._check_cometml_experiment_tampering(node)
        
        # AIML219: TensorBoard remote code execution
        self._check_tensorboard_rce(node)
        
        # AIML220: Neptune.ai model manipulation
        self._check_neptuneai_model_manipulation(node)
        
        # AIML221: Experiment metadata injection
        self._check_experiment_metadata_injection(node)
        
        # AIML222: Metric tampering
        self._check_metric_tampering(node)
        
        # AIML223: Artifact poisoning
        self._check_artifact_poisoning(node)
        
        # AIML224: Run comparison manipulation
        self._check_run_comparison_manipulation(node)
        
        # AIML225: Hyperparameter logging risks
        self._check_hyperparameter_logging_risks(node)
        
        # Phase 2.3: Model Deployment & Serving (35 checks)
        # Phase 2.3.1: Model Serving Vulnerabilities (15 checks - AIML226-AIML240)
        # AIML226: TorchServe vulnerabilities
        self._check_torchserve_vulnerabilities(node)
        
        # AIML227: TensorFlow Serving injection
        self._check_tensorflow_serving_injection(node)
        
        # AIML228: ONNX Runtime risks
        self._check_onnx_runtime_risks(node)
        
        # AIML229: Triton Inference Server gaps
        self._check_triton_inference_server_gaps(node)
        
        # AIML230: BentoML security issues
        self._check_bentoml_security_issues(node)
        
        # AIML231: Ray Serve vulnerabilities
        self._check_ray_serve_vulnerabilities(node)
        
        # AIML232: Seldon Core risks
        self._check_seldon_core_risks(node)
        
        # AIML233: KServe weaknesses
        self._check_kserve_weaknesses(node)
        
        # AIML234: Model batching attacks
        self._check_model_batching_attacks(node)
        
        # AIML235: Dynamic batching poisoning
        self._check_dynamic_batching_poisoning(node)
        
        # AIML236: Model versioning bypass
        self._check_model_versioning_bypass(node)
        
        # AIML237: A/B testing manipulation
        self._check_ab_testing_manipulation(node)
        
        # AIML238: Canary deployment risks
        self._check_canary_deployment_risks(node)
        
        # AIML239: Blue-green deployment gaps
        self._check_blue_green_deployment_gaps(node)
        
        # AIML240: Shadow deployment leakage
        self._check_shadow_deployment_leakage(node)
        
        # Phase 2.3.2: API & Endpoint Security (12 checks - AIML241-AIML252)
        # AIML241: Missing authentication on inference API
        self._check_missing_authentication_inference_api(node)
        
        # AIML242: Model endpoint enumeration
        self._check_model_endpoint_enumeration(node)
        
        # AIML243: Batch inference injection
        self._check_batch_inference_injection(node)
        
        # AIML244: Streaming inference attacks
        self._check_streaming_inference_attacks(node)
        
        # AIML245: Model cache poisoning
        self._check_model_cache_poisoning(node)
        
        # AIML246: Prediction logging risks (PII)
        self._check_prediction_logging_risks(node)
        
        # AIML247: Model warm-up vulnerabilities
        self._check_model_warmup_vulnerabilities(node)
        
        # AIML248: Health check information disclosure
        self._check_health_check_information_disclosure(node)
        
        # AIML249: Metrics endpoint exposure
        self._check_metrics_endpoint_exposure(node)
        
        # AIML250: Model metadata leakage
        self._check_model_metadata_leakage(node)
        
        # AIML251: Feature flag manipulation
        self._check_feature_flag_manipulation(node)
        
        # AIML252: Circuit breaker bypass
        self._check_circuit_breaker_bypass(node)
        
        # Phase 2.3.3: Edge & Mobile Deployment (8 checks - AIML253-AIML260)
        # AIML253: TFLite model tampering
        self._check_tflite_model_tampering(node)
        
        # AIML254: Core ML injection
        self._check_coreml_injection(node)
        
        # AIML255: ONNX mobile risks
        self._check_onnx_mobile_risks(node)
        
        # AIML256: Quantized model vulnerabilities
        self._check_quantized_model_vulnerabilities(node)
        
        # AIML257: Model pruning attacks
        self._check_model_pruning_attacks(node)
        
        # AIML258: Knowledge distillation risks
        self._check_knowledge_distillation_risks(node)
        
        # AIML259: On-device training weaknesses
        self._check_on_device_training_weaknesses(node)
        
        # AIML260: Federated learning gaps
        self._check_federated_learning_gaps(node)
        
        # Phase 2.4: Model Monitoring & Observability (20 checks)
        # Phase 2.4.1: Drift Detection Security (10 checks - AIML261-AIML270)
        # AIML261: Data drift detection bypass
        self._check_data_drift_detection_bypass(node)
        
        # AIML262: Concept drift manipulation
        self._check_concept_drift_manipulation(node)
        
        # AIML263: Model performance degradation hiding
        self._check_model_performance_degradation_hiding(node)
        
        # AIML264: Prediction distribution poisoning
        self._check_prediction_distribution_poisoning(node)
        
        # AIML265: Monitoring pipeline injection
        self._check_monitoring_pipeline_injection(node)
        
        # AIML266: Alert threshold manipulation
        self._check_alert_threshold_manipulation(node)
        
        # AIML267: Logging framework vulnerabilities
        self._check_logging_framework_vulnerabilities(node)
        
        # AIML268: Missing drift detection
        self._check_missing_drift_detection(node)
        
        # AIML269: Statistical test manipulation
        self._check_statistical_test_manipulation(node)
        
        # AIML270: Ground truth poisoning
        self._check_ground_truth_poisoning(node)
        
        # Phase 2.4.2: Explainability & Interpretability (10 checks - AIML271-AIML280)
        # AIML271: SHAP value manipulation
        self._check_shap_value_manipulation(node)
        
        # AIML272: LIME explanation poisoning
        self._check_lime_explanation_poisoning(node)
        
        # AIML273: Feature importance injection
        self._check_feature_importance_injection(node)
        
        # AIML274: Saliency map tampering
        self._check_saliency_map_tampering(node)
        
        # AIML275: Attention weight manipulation
        self._check_attention_weight_manipulation(node)
        
        # AIML276: Counterfactual explanation attacks
        self._check_counterfactual_explanation_attacks(node)
        
        # AIML277: Model card injection
        self._check_model_card_injection(node)
        
        # AIML278: Explanation dashboard vulnerabilities
        self._check_explanation_dashboard_vulnerabilities(node)
        
        # AIML279: Fairness metric manipulation
        self._check_fairness_metric_manipulation(node)
        
        # AIML280: Bias detection bypass
        self._check_bias_detection_bypass(node)
        
        # Phase 3: Specialized AI/ML Frameworks (100 checks - AIML281-AIML380)
        # Phase 3.1: Computer Vision Security (35 checks)
        # Phase 3.1.1: Image Processing Vulnerabilities (15 checks - AIML281-AIML295)
        # AIML281: OpenCV injection attacks
        self._check_opencv_injection_attacks(node)
        
        # AIML282: PIL/Pillow buffer overflows
        self._check_pillow_buffer_overflows(node)
        
        # AIML283: Image augmentation poisoning
        self._check_image_augmentation_poisoning(node)
        
        # AIML284: EXIF metadata injection
        self._check_exif_metadata_injection(node)
        
        # AIML285: Adversarial patch attacks
        self._check_adversarial_patch_attacks(node)
        
        # AIML286: Texture synthesis manipulation
        self._check_texture_synthesis_manipulation(node)
        
        # AIML287: Style transfer poisoning
        self._check_style_transfer_poisoning(node)
        
        # AIML288: Super-resolution attacks
        self._check_super_resolution_attacks(node)
        
        # AIML289: Image segmentation manipulation
        self._check_image_segmentation_manipulation(node)
        
        # AIML290: Object detection bypass
        self._check_object_detection_bypass(node)
        
        # AIML291: Facial recognition spoofing
        self._check_facial_recognition_spoofing(node)
        
        # AIML292: OCR injection attacks
        self._check_ocr_injection_attacks(node)
        
        # AIML293: Image captioning poisoning
        self._check_image_captioning_poisoning(node)
        
        # AIML294: Visual question answering attacks
        self._check_visual_question_answering_attacks(node)
        
        # AIML295: Video frame injection
        self._check_video_frame_injection(node)
        
        # Phase 3.1.2: Vision Transformers (10 checks - AIML296-AIML305)
        # AIML296: Patch embedding manipulation
        self._check_patch_embedding_manipulation(node)
        
        # AIML297: Position encoding injection
        self._check_position_encoding_injection(node)
        
        # AIML298: Attention mechanism attacks
        self._check_attention_mechanism_attacks(node)
        
        # AIML299: Vision-language model risks (CLIP)
        self._check_vision_language_model_risks(node)
        
        # AIML300: Diffusion model injection (Stable Diffusion)
        self._check_diffusion_model_injection(node)
        
        # AIML301: Text-to-image prompt injection
        self._check_text_to_image_prompt_injection(node)
        
        # AIML302: Image-to-image manipulation
        self._check_image_to_image_manipulation(node)
        
        # AIML303: Inpainting attacks
        self._check_inpainting_attacks(node)
        
        # AIML304: Outpainting vulnerabilities
        self._check_outpainting_vulnerabilities(node)
        
        # AIML305: Multimodal fusion risks
        self._check_multimodal_fusion_risks(node)
        
        # Phase 3.1.3: CNN & Architecture Security (10 checks - AIML306-AIML315)
        # AIML306: ResNet skip connection attacks
        self._check_resnet_skip_connection_attacks(node)
        
        # AIML307: DenseNet feature concatenation
        self._check_densenet_feature_concatenation(node)
        
        # AIML308: EfficientNet scaling manipulation
        self._check_efficientnet_scaling_manipulation(node)
        
        # AIML309: MobileNet depthwise convolution risks
        self._check_mobilenet_depthwise_convolution_risks(node)
        
        # AIML310: SqueezeNet fire module injection
        self._check_squeezenet_fire_module_injection(node)
        
        # AIML311: Neural architecture search poisoning
        self._check_neural_architecture_search_poisoning(node)
        
        # AIML312: Activation function vulnerabilities
        self._check_activation_function_vulnerabilities(node)
        
        # AIML313: Pooling layer manipulation
        self._check_pooling_layer_manipulation(node)
        
        # AIML314: Dropout bypass techniques
        self._check_dropout_bypass_techniques(node)
        
        # AIML315: Batch normalization attacks
        self._check_batch_normalization_attacks(node)
        
        # Phase 3.2: Natural Language Processing Security (35 checks - AIML316-AIML350)
        # Phase 3.2.1: Text Processing Security (15 checks - AIML316-AIML330)
        # AIML316: Tokenization injection
        self._check_tokenization_injection(node)
        
        # AIML317: Subword tokenization bypass
        self._check_subword_tokenization_bypass(node)
        
        # AIML318: BPE manipulation
        self._check_bpe_manipulation(node)
        
        # AIML319: WordPiece attack vectors
        self._check_wordpiece_attack_vectors(node)
        
        # AIML320: SentencePiece vulnerabilities
        self._check_sentencepiece_vulnerabilities(node)
        
        # AIML321: Text normalization bypass
        self._check_text_normalization_bypass(node)
        
        # AIML322: Stop word removal manipulation
        self._check_stopword_removal_manipulation(node)
        
        # AIML323: Stemming/lemmatization attacks
        self._check_stemming_lemmatization_attacks(node)
        
        # AIML324: Named entity recognition injection
        self._check_ner_injection(node)
        
        # AIML325: POS tagging manipulation
        self._check_pos_tagging_manipulation(node)
        
        # AIML326: Dependency parsing poisoning
        self._check_dependency_parsing_poisoning(node)
        
        # AIML327: Sentiment analysis bias
        self._check_sentiment_analysis_bias(node)
        
        # AIML328: Text classification backdoors
        self._check_text_classification_backdoors(node)
        
        # AIML329: Sequence labeling attacks
        self._check_sequence_labeling_attacks(node)
        
        # AIML330: Coreference resolution manipulation
        self._check_coreference_resolution_manipulation(node)
        
        # Phase 3.2.2: Transformer Architectures (12 checks - AIML331-AIML342)
        # AIML331: BERT fine-tuning injection
        self._check_bert_finetuning_injection(node)
        
        # AIML332: GPT prompt engineering attacks
        self._check_gpt_prompt_engineering_attacks(node)
        
        # AIML333: T5 encoder-decoder manipulation
        self._check_t5_encoder_decoder_manipulation(node)
        
        # AIML334: BART denoising poisoning
        self._check_bart_denoising_poisoning(node)
        
        # AIML335: RoBERTa masked language modeling
        self._check_roberta_masked_lm(node)
        
        # AIML336: ELECTRA discriminator/generator attacks
        self._check_electra_attacks(node)
        
        # AIML337: XLNet permutation language modeling
        self._check_xlnet_permutation_lm(node)
        
        # AIML338: ALBERT parameter sharing risks
        self._check_albert_parameter_sharing_risks(node)
        
        # AIML339: DistilBERT knowledge distillation
        self._check_distilbert_knowledge_distillation(node)
        
        # AIML340: DeBERTa disentangled attention
        self._check_deberta_disentangled_attention(node)
        
        # AIML341: Longformer sliding window attacks
        self._check_longformer_sliding_window_attacks(node)
        
        # AIML342: BigBird sparse attention manipulation
        self._check_bigbird_sparse_attention_manipulation(node)
        
        # Phase 3.2.3: Embeddings & Representations (8 checks - AIML343-AIML350)
        # AIML343: Word2Vec poisoning
        self._check_word2vec_poisoning(node)
        
        # AIML344: GloVe embedding manipulation
        self._check_glove_embedding_manipulation(node)
        
        # AIML345: FastText subword attacks
        self._check_fasttext_subword_attacks(node)
        
        # AIML346: ELMo contextualized embedding injection
        self._check_elmo_contextualized_embedding_injection(node)
        
        # AIML347: Sentence-BERT manipulation
        self._check_sentence_bert_manipulation(node)
        
        # AIML348: Universal Sentence Encoder risks
        self._check_universal_sentence_encoder_risks(node)
        
        # AIML349: Doc2Vec document poisoning
        self._check_doc2vec_document_poisoning(node)
        
        # AIML350: Graph embedding attacks
        self._check_graph_embedding_attacks(node)
        
        # AIML007: Insecure model serialization
        self._check_insecure_serialization(node)
        
        # AIML008: Missing input validation
        self._check_missing_input_validation(node)
        
        # AIML009: GPU memory leakage
        self._check_gpu_memory_leakage(node)
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for AI/ML security issues in assignments."""
        # AIML001: Check for prompt injection in assignments (f-strings, .format())
        if self.has_llm_framework:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Check if this looks like a prompt variable
                    if "prompt" in var_name.lower() or "message" in var_name.lower() or "text" in var_name.lower() or "query" in var_name.lower() or "content" in var_name.lower() or "msg" in var_name.lower() or "input" in var_name.lower() or "user" in var_name.lower():
                        # Check if using f-string
                        if isinstance(node.value, ast.JoinedStr):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="AIML001",
                                    category=RuleCategory.SECURITY,
                                    severity=RuleSeverity.CRITICAL,
                                    message="Potential prompt injection: F-string used for LLM prompt with user input",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    end_line_number=getattr(node, "end_lineno", node.lineno),
                                    end_column=getattr(node, "end_col_offset", node.col_offset),
                                    file_path=str(self.file_path),
                                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data=None,
                                    owasp_id="LLM01",
                                    cwe_id="CWE-94",
                                    source_tool="pyguard",
                                )
                            )
                        # Check if using .format()
                        elif isinstance(node.value, ast.Call):
                            if isinstance(node.value.func, ast.Attribute):
                                if node.value.func.attr == "format":
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="AIML001",
                                            category=RuleCategory.SECURITY,
                                            severity=RuleSeverity.CRITICAL,
                                            message="Potential prompt injection: .format() used for LLM prompt with user input",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            end_line_number=getattr(node, "end_lineno", node.lineno),
                                            end_column=getattr(node, "end_col_offset", node.col_offset),
                                            file_path=str(self.file_path),
                                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                            fix_applicability=FixApplicability.SAFE,
                                            fix_data=None,
                                            owasp_id="LLM01",
                                            cwe_id="CWE-94",
                                            source_tool="pyguard",
                                        )
                                    )
                        # AIML011-AIML022: Check for various prompt injection patterns in string constants
                        elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            self._check_string_for_prompt_override(node.value.value, node)
                            self._check_string_for_unicode_injection(node.value.value, node)
                            self._check_string_for_role_confusion(node.value.value, node)
                            self._check_string_for_instruction_concatenation(node.value.value, node)
                            self._check_string_for_multilanguage_injection(node.value.value, node)
                            self._check_string_for_markdown_injection(node.value.value, node)
                            self._check_string_for_payload_injection(node.value.value, node)
                            self._check_string_for_sql_comment_injection(node.value.value, node)
                            self._check_string_for_escape_sequence_injection(node.value.value, node)
                            self._check_string_for_token_stuffing(node.value.value, node)
                            self._check_string_for_recursive_prompt_injection(node.value.value, node)
                            self._check_string_for_base64_injection(node.value.value, node)
                            self._check_string_for_rot13_obfuscation(node.value.value, node)
                            self._check_string_for_invisible_char_injection(node.value.value, node)
                            self._check_string_for_bidi_override(node.value.value, node)
                            self._check_string_for_template_literal_injection(node.value.value, node)
                            self._check_string_for_variable_substitution(node.value.value, node)
                            self._check_string_for_context_window_overflow(node.value.value, node)
                            self._check_string_for_attention_manipulation(node.value.value, node)
        
        # AIML002: Model inversion risks
        self._check_model_inversion(node)
        
        # AIML003: Training data poisoning
        self._check_training_data_poisoning(node)
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for AI/ML security issues."""
        # AIML005: Model extraction vulnerabilities
        self._check_model_extraction(node)
        
        # AIML006: AI bias detection
        self._check_ai_bias(node)
        
        # AIML010: Federated learning privacy
        self._check_federated_learning(node)
        
        self.generic_visit(node)

    def _check_prompt_injection(self, node: ast.Call) -> None:
        """AIML001: Detect prompt injection vulnerabilities in LLM applications."""
        if not self.has_llm_framework:
            return
            
        # Check for string formatting with user input in prompts
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["create", "complete", "generate", "chat"]:
                for arg in node.args:
                    if self._contains_user_input(arg):
                        violation = RuleViolation(
                            rule_id="AIML001",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.CRITICAL,
                            message="Potential prompt injection: User input concatenated directly into LLM prompt",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM01",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_system_prompt_override(self, node: ast.Call) -> None:
        """AIML011: Detect system prompt override attempts (delimiter injection)."""
        if not self.has_llm_framework:
            return
        
        # Check for dangerous delimiter patterns in function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_prompt_override(arg.value, node)
                    
        # Also check for delimiter injection in keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_prompt_override(keyword.value.value, node)
    
    def _check_string_for_prompt_override(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains prompt override patterns."""
        if not self.has_llm_framework:
            return
            
        # Check for dangerous delimiter patterns in string literals
        dangerous_patterns = [
            "ignore previous instructions",
            "ignore above",
            "ignore all previous",
            "new system message",
            "system:",
            "assistant:",
            "you are now",
            "forget everything",
            "disregard previous",
        ]
        
        lower_val = text.lower()
        if any(pattern in lower_val for pattern in dangerous_patterns):
            violation = RuleViolation(
                rule_id="AIML011",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.CRITICAL,
                message="System prompt override attempt detected: delimiter injection pattern",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
            
    def _check_unicode_injection(self, node: ast.Call) -> None:
        """AIML012: Detect Unicode/homoglyph injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_unicode_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_unicode_injection(keyword.value.value, node)
    
    def _check_string_for_unicode_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Unicode injection patterns."""
        if not self.has_llm_framework:
            return
            
        # Check for Unicode/homoglyph patterns
        suspicious_unicode_ranges = [
            (0x200B, 0x200F),  # Zero-width characters
            (0x202A, 0x202E),  # Bi-directional text overrides
            (0xFEFF, 0xFEFF),  # Zero-width no-break space
        ]
        
        def contains_suspicious_unicode(text: str) -> bool:
            """Check if text contains suspicious Unicode characters."""
            for char in text:
                code_point = ord(char)
                for start, end in suspicious_unicode_ranges:
                    if start <= code_point <= end:
                        return True
            return False
        
        if contains_suspicious_unicode(text):
            violation = RuleViolation(
                rule_id="AIML012",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Unicode injection detected: suspicious zero-width or bi-directional characters",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_role_confusion(self, node: ast.Call) -> None:
        """AIML013: Detect role confusion attacks (DAN mode, jailbreaks)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_role_confusion(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_role_confusion(keyword.value.value, node)
    
    def _check_string_for_role_confusion(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains role confusion patterns."""
        if not self.has_llm_framework:
            return
        
        # Role confusion patterns - DAN mode, jailbreaks
        role_confusion_patterns = [
            "dan mode",
            "do anything now",
            "developer mode",
            "jailbreak",
            "unrestricted mode",
            "act as if",
            "pretend you are",
            "simulate being",
            "roleplay as",
            "you are now a",
            "switch to",
            "enable dev mode",
            "unlock",
        ]
        
        lower_text = text.lower()
        if any(pattern in lower_text for pattern in role_confusion_patterns):
            violation = RuleViolation(
                rule_id="AIML013",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.CRITICAL,
                message="Role confusion attack detected: DAN mode or jailbreak attempt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_instruction_concatenation(self, node: ast.Call) -> None:
        """AIML014: Detect instruction concatenation bypasses."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_instruction_concatenation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_instruction_concatenation(keyword.value.value, node)
    
    def _check_string_for_instruction_concatenation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains instruction concatenation patterns."""
        if not self.has_llm_framework:
            return
        
        # Instruction concatenation patterns - multiple newlines or delimiter sequences
        concatenation_indicators = [
            "\n\n\n",  # Multiple newlines
            "---",     # Delimiter sequence
            "###",     # Markdown header delimiters
            "===",     # Another delimiter
            "***",     # Another delimiter
        ]
        
        # Also check for instruction keywords after delimiters
        instruction_keywords = ["new instruction:", "new task:", "new prompt:", "override:", "update:"]
        
        has_delimiter = any(delimiter in text for delimiter in concatenation_indicators)
        has_instruction = any(keyword in text.lower() for keyword in instruction_keywords)
        
        if has_delimiter and has_instruction:
            violation = RuleViolation(
                rule_id="AIML014",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Instruction concatenation bypass detected: delimiter followed by instruction keywords",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_multilanguage_injection(self, node: ast.Call) -> None:
        """AIML015: Detect multi-language prompt injection (non-English)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_multilanguage_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_multilanguage_injection(keyword.value.value, node)
    
    def _check_string_for_multilanguage_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains multi-language injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Common prompt injection phrases in other languages
        multilang_patterns = [
            # Chinese (Simplified)
            "忽略以上",  # ignore above
            "忽略之前",  # ignore previous
            "新指令",    # new instruction
            # Spanish (case-insensitive)
            ("ignorar instrucciones anteriores", True),
            ("nueva instrucción", True),
            # French (case-insensitive)
            ("ignorer les instructions précédentes", True),
            ("nouvelle instruction", True),
            # German (case-insensitive)
            ("vorherige anweisungen ignorieren", True),
            ("neue anweisung", True),
            # Russian (Cyrillic)
            "игнорировать предыдущие",
            "новая инструкция",
            # Japanese
            "以前の指示を無視",
            "新しい指示",
            # Korean
            "이전 지시 무시",
            "새로운 지시",
        ]
        
        lower_text = text.lower()
        for pattern in multilang_patterns:
            # Handle tuple patterns (pattern, case_insensitive)
            if isinstance(pattern, tuple):
                pattern_text, case_insensitive = pattern
                if case_insensitive:
                    if pattern_text.lower() in lower_text:
                        matched = True
                        break
                else:
                    if pattern_text in text:
                        matched = True
                        break
            else:
                # Direct string match (for non-Latin scripts)
                if pattern in text:
                    matched = True
                    break
        else:
            matched = False
        
        if matched:
            violation = RuleViolation(
                rule_id="AIML015",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Multi-language prompt injection detected: non-English prompt manipulation attempt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_markdown_injection(self, node: ast.Call) -> None:
        """AIML016: Detect Markdown injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_markdown_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_markdown_injection(keyword.value.value, node)
    
    def _check_string_for_markdown_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Markdown injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Markdown patterns that could be used for injection
        markdown_injection_patterns = [
            "](javascript:",  # Markdown link with javascript protocol
            "](data:",        # Markdown link with data protocol
            "](file:",        # Markdown link with file protocol
            "![",             # Image embedding
            "<script",        # Script tag in markdown
            "<iframe",        # Iframe tag in markdown
            "```javascript",  # JavaScript code block
            "```html",        # HTML code block
        ]
        
        lower_text = text.lower()
        if any(pattern in lower_text for pattern in markdown_injection_patterns):
            violation = RuleViolation(
                rule_id="AIML016",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Markdown injection detected: potentially malicious markdown constructs in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_payload_injection(self, node: ast.Call) -> None:
        """AIML017: Detect XML/JSON payload injection."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_payload_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_payload_injection(keyword.value.value, node)
    
    def _check_string_for_payload_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains XML/JSON payload injection patterns."""
        if not self.has_llm_framework:
            return
        
        # XML/JSON payload injection patterns
        payload_patterns = [
            "<system>",       # XML system tag
            "</system>",      # XML system closing tag
            "<instruction>",  # XML instruction tag
            '"role":',        # JSON role field
            '"system":',      # JSON system field
            '{"role": "system"',  # JSON system role
            "<assistant>",    # XML assistant tag
            '"content":',     # JSON content field
        ]
        
        lower_text = text.lower()
        
        # Count suspicious patterns
        suspicious_count = sum(1 for pattern in payload_patterns if pattern in lower_text)
        
        # Flag if multiple payload indicators present
        if suspicious_count >= 2:
            violation = RuleViolation(
                rule_id="AIML017",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="XML/JSON payload injection detected: structured payload manipulation in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_sql_comment_injection(self, node: ast.Call) -> None:
        """AIML018: Detect SQL-style comment injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_sql_comment_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_sql_comment_injection(keyword.value.value, node)
    
    def _check_string_for_sql_comment_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains SQL-style comment injection patterns."""
        if not self.has_llm_framework:
            return
        
        # SQL-style comment patterns used for prompt injection
        sql_comment_patterns = [
            "-- ",          # SQL single-line comment
            "--\n",         # SQL comment with newline
            "--\r",         # SQL comment with carriage return
            "/* ",          # SQL multi-line comment start
            " */",          # SQL multi-line comment end
            "#ignore",      # Hash comment with injection keyword
            "-- ignore",    # SQL comment with ignore
            "/* ignore",    # Multi-line comment with ignore
        ]
        
        # Also check for patterns that combine comments with instructions
        has_comment = any(pattern in text for pattern in sql_comment_patterns)
        has_instruction_after_comment = False
        
        if has_comment:
            # Check if there's an instruction keyword after the comment
            instruction_keywords = ["ignore", "bypass", "override", "new", "system", "admin"]
            lower_text = text.lower()
            has_instruction_after_comment = any(keyword in lower_text for keyword in instruction_keywords)
        
        if has_comment and has_instruction_after_comment:
            violation = RuleViolation(
                rule_id="AIML018",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="SQL-style comment injection detected: comment syntax used for prompt manipulation",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_escape_sequence_injection(self, node: ast.Call) -> None:
        """AIML019: Detect escape sequence injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_escape_sequence_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_escape_sequence_injection(keyword.value.value, node)
    
    def _check_string_for_escape_sequence_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains escape sequence injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Escape sequence patterns that could be used for injection
        # Looking for patterns like actual newlines (Python has already processed escape sequences)
        # Check for multiple consecutive newlines
        has_multiple_newlines = "\n\n\n" in text
        has_multiple_crlf = "\r\n\r\n" in text
        has_null_byte = "\x00" in text
        has_escape_char = "\x1b" in text or "\033" in text
        
        # Count suspicious patterns
        suspicious_count = sum([
            has_multiple_newlines,
            has_multiple_crlf,
            has_null_byte,
            has_escape_char
        ])
        
        # Also check for these patterns followed by instruction keywords
        has_escape_with_instruction = False
        if suspicious_count > 0:
            instruction_keywords = ["new", "system", "ignore", "override", "instruction"]
            lower_text = text.lower()
            has_escape_with_instruction = any(keyword in lower_text for keyword in instruction_keywords)
        
        if suspicious_count >= 1 and has_escape_with_instruction:
            violation = RuleViolation(
                rule_id="AIML019",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Escape sequence injection detected: suspicious escape sequences in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_token_stuffing(self, node: ast.Call) -> None:
        """AIML020: Detect token stuffing attacks (context window exhaustion)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments for very long strings
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_token_stuffing(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_token_stuffing(keyword.value.value, node)
    
    def _check_string_for_token_stuffing(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string is attempting token stuffing."""
        if not self.has_llm_framework:
            return
        
        # Token stuffing indicators:
        # 1. Very long strings (>8000 chars is suspicious)
        # 2. Highly repetitive content
        text_length = len(text)
        
        if text_length > 8000:
            # Check for repetitiveness (same pattern repeated many times)
            # Simple heuristic: if the first 100 chars appear multiple times, it's repetitive
            if text_length > 200:
                sample = text[:100]
                occurrences = text.count(sample)
                if occurrences > 10:  # Very repetitive
                    violation = RuleViolation(
                        rule_id="AIML020",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message=f"Token stuffing attack detected: very long ({text_length} chars) repetitive prompt",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_recursive_prompt_injection(self, node: ast.Call) -> None:
        """AIML021: Detect recursive prompt injection (prompts containing prompts)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_recursive_prompt_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_recursive_prompt_injection(keyword.value.value, node)
    
    def _check_string_for_recursive_prompt_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains recursive prompt injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Recursive prompt injection patterns - prompts within prompts
        recursive_patterns = [
            "prompt:",
            "user:",
            "assistant:",
            "system:",
            "generate a prompt",
            "create a prompt",
            "write a prompt",
            "respond to:",
            "answer:",
        ]
        
        lower_text = text.lower()
        pattern_count = sum(1 for pattern in recursive_patterns if pattern in lower_text)
        
        # If multiple prompt-related keywords, likely recursive
        if pattern_count >= 2:
            violation = RuleViolation(
                rule_id="AIML021",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Recursive prompt injection detected: prompt contains nested prompt instructions",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_base64_injection(self, node: ast.Call) -> None:
        """AIML022: Detect Base64 encoded injection attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_base64_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_base64_injection(keyword.value.value, node)
    
    def _check_string_for_base64_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Base64 encoded injection attempts."""
        if not self.has_llm_framework:
            return
        
        # Base64 pattern detection
        # Look for Base64-like strings (alphanumeric + / and + with = padding)
        import re
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        if matches:
            # Try to decode and check for malicious patterns
            try:
                import base64
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        # Check if decoded text contains injection keywords
                        malicious_keywords = ["ignore", "system", "bypass", "override", "admin", "jailbreak"]
                        if any(keyword in decoded.lower() for keyword in malicious_keywords):
                            violation = RuleViolation(
                                rule_id="AIML022",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="Base64 encoded injection detected: encoded malicious content in prompt",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.SAFE,
                                fix_data=None,
                                owasp_id="LLM01",
                                cwe_id="CWE-94",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                            break
                    except Exception:
                        # Invalid Base64, skip
                        continue
            except ImportError:
                # base64 module not available, skip
                pass

    def _check_rot13_obfuscation(self, node: ast.Call) -> None:
        """AIML023: Detect ROT13/Caesar cipher obfuscation in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_rot13_obfuscation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_rot13_obfuscation(keyword.value.value, node)
    
    def _check_string_for_rot13_obfuscation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains ROT13 or Caesar cipher obfuscation."""
        if not self.has_llm_framework:
            return
        
        # Check for ROT13 encoded text by looking for patterns
        # ROT13 characteristic: high concentration of unusual letter patterns
        # Simple heuristic: check if decoding with ROT13 produces more common English words
        import codecs
        try:
            # Try ROT13 decode
            decoded = codecs.decode(text, 'rot_13')
            
            # Check if decoded text contains malicious keywords
            malicious_keywords = ["ignore", "system", "bypass", "override", "admin", "jailbreak", "instruction"]
            lower_decoded = decoded.lower()
            
            # Also check original text doesn't contain these keywords (to avoid false positives)
            lower_text = text.lower()
            has_keywords_in_decoded = any(keyword in lower_decoded for keyword in malicious_keywords)
            has_keywords_in_original = any(keyword in lower_text for keyword in malicious_keywords)
            
            # If decoded has keywords but original doesn't, likely ROT13 obfuscation
            if has_keywords_in_decoded and not has_keywords_in_original and len(text) > 10:
                violation = RuleViolation(
                    rule_id="AIML023",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="ROT13/Caesar cipher obfuscation detected: encoded malicious content in prompt",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
        except Exception:
            # ROT13 decode failed, skip
            pass
    
    def _check_invisible_char_injection(self, node: ast.Call) -> None:
        """AIML024: Detect invisible character injection (zero-width spaces)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_invisible_char_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_invisible_char_injection(keyword.value.value, node)
    
    def _check_string_for_invisible_char_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains invisible character injection."""
        if not self.has_llm_framework:
            return
        
        # Invisible/zero-width characters that can be used for injection
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space (BOM)
            '\u180e',  # Mongolian vowel separator
            '\u00ad',  # Soft hyphen
        ]
        
        # Count invisible characters
        invisible_count = sum(text.count(char) for char in invisible_chars)
        
        if invisible_count > 0:
            # Check if there are also instruction keywords (suggests malicious intent)
            malicious_keywords = ["ignore", "system", "bypass", "override", "instruction"]
            has_keywords = any(keyword in text.lower() for keyword in malicious_keywords)
            
            if has_keywords or invisible_count >= 3:
                violation = RuleViolation(
                    rule_id="AIML024",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message=f"Invisible character injection detected: {invisible_count} zero-width characters in prompt",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bidi_override(self, node: ast.Call) -> None:
        """AIML025: Detect right-to-left override attacks (Unicode bidi)."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_bidi_override(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_bidi_override(keyword.value.value, node)
    
    def _check_string_for_bidi_override(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains Unicode bidi override attacks."""
        if not self.has_llm_framework:
            return
        
        # Unicode bidirectional text control characters
        bidi_chars = [
            '\u202a',  # Left-to-right embedding
            '\u202b',  # Right-to-left embedding
            '\u202c',  # Pop directional formatting
            '\u202d',  # Left-to-right override
            '\u202e',  # Right-to-left override
            '\u2066',  # Left-to-right isolate
            '\u2067',  # Right-to-left isolate
            '\u2068',  # First strong isolate
            '\u2069',  # Pop directional isolate
        ]
        
        # Count bidi control characters
        bidi_count = sum(text.count(char) for char in bidi_chars)
        
        if bidi_count > 0:
            violation = RuleViolation(
                rule_id="AIML025",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message=f"Unicode bidirectional override detected: {bidi_count} bidi control characters in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_template_literal_injection(self, node: ast.Call) -> None:
        """AIML026: Detect prompt template literal injection."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_template_literal_injection(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_template_literal_injection(keyword.value.value, node)
    
    def _check_string_for_template_literal_injection(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains template literal injection patterns."""
        if not self.has_llm_framework:
            return
        
        # Template literal injection patterns
        template_patterns = [
            "${",          # JavaScript template literal
            "{{",          # Jinja2/Handlebars template
            "{%",          # Jinja2 control
            "<%",          # ERB/EJS template
            "[[",          # Custom template syntax
            "<<",          # Heredoc-style templates
        ]
        
        # Check for template patterns
        has_template = any(pattern in text for pattern in template_patterns)
        
        if has_template:
            # Check if there are also injection keywords
            injection_keywords = ["eval", "exec", "import", "system", "process", "require"]
            has_injection = any(keyword in text.lower() for keyword in injection_keywords)
            
            if has_injection:
                violation = RuleViolation(
                    rule_id="AIML026",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Template literal injection detected: template syntax with dangerous code execution patterns",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_fstring_injection(self, node: ast.Call) -> None:
        """AIML027: Detect F-string injection in prompts."""
        if not self.has_llm_framework:
            return
        
        # Check for f-string usage in arguments
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                # This is an f-string
                violation = RuleViolation(
                    rule_id="AIML027",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
        
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.JoinedStr):
                violation = RuleViolation(
                    rule_id="AIML027",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_variable_substitution(self, node: ast.Call) -> None:
        """AIML028: Detect variable substitution attacks."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_variable_substitution(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_variable_substitution(keyword.value.value, node)
    
    def _check_string_for_variable_substitution(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string contains variable substitution attacks."""
        if not self.has_llm_framework:
            return
        
        # Variable substitution patterns that could be exploited
        substitution_patterns = [
            "$(",          # Shell command substitution
            "`",           # Backtick command substitution
            "${env:",      # Environment variable access
            "${var:",      # Variable interpolation
            "$(whoami)",   # Common attack pattern
            "${PATH}",     # Environment variable
            "$USER",       # Environment variable
        ]
        
        # Check for substitution patterns
        has_substitution = any(pattern in text for pattern in substitution_patterns)
        
        if has_substitution:
            violation = RuleViolation(
                rule_id="AIML028",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Variable substitution attack detected: shell/environment variable substitution in prompt",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_context_window_overflow(self, node: ast.Call) -> None:
        """AIML029: Detect context window overflow attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_context_window_overflow(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_context_window_overflow(keyword.value.value, node)
    
    def _check_string_for_context_window_overflow(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string attempts context window overflow."""
        if not self.has_llm_framework:
            return
        
        # Context window overflow indicators:
        # 1. Extremely long text (>32000 chars is suspicious for most LLMs)
        # 2. Repetitive patterns designed to fill context
        text_length = len(text)
        
        if text_length > 32000:
            violation = RuleViolation(
                rule_id="AIML029",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message=f"Context window overflow detected: extremely long prompt ({text_length} chars)",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-400",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_attention_manipulation(self, node: ast.Call) -> None:
        """AIML030: Detect attention mechanism manipulation attempts."""
        if not self.has_llm_framework:
            return
        
        # Check function call arguments
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self._check_string_for_attention_manipulation(arg.value, node)
                    
        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                self._check_string_for_attention_manipulation(keyword.value.value, node)
    
    def _check_string_for_attention_manipulation(self, text: str, node: ast.AST) -> None:
        """Helper to check if a string attempts to manipulate attention mechanisms."""
        if not self.has_llm_framework:
            return
        
        # Attention manipulation patterns
        attention_patterns = [
            "pay attention to",
            "focus on",
            "most important",
            "critical:",
            "priority:",
            "emphasis:",
            "highlight:",
            "**important**",
            "!!!",
            "URGENT",
            "CRITICAL",
        ]
        
        # Check for attention manipulation combined with instruction changes
        has_attention = any(pattern in text.lower() for pattern in [p.lower() for p in attention_patterns])
        
        if has_attention:
            # Check if combined with instruction keywords
            instruction_keywords = ["ignore", "override", "bypass", "forget", "new instruction", "disregard"]
            has_instruction = any(keyword in text.lower() for keyword in instruction_keywords)
            
            if has_instruction:
                violation = RuleViolation(
                    rule_id="AIML030",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Attention manipulation detected: emphasis markers combined with instruction override attempts",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_url_based_injection(self, node: ast.Call) -> None:
        """AIML031: Detect URL-based injection (fetched web content)."""
        if not self.has_llm_framework:
            return
        
        # Check for requests/urllib usage before LLM calls (indicates external content fetching)
        if isinstance(node.func, ast.Attribute):
            # Look for patterns like: content = requests.get(url).text; llm.generate(content)
            if node.func.attr in ["get", "post", "fetch", "retrieve", "download"]:
                # This is a potential external content fetch
                # Flag if used in LLM context
                violation = RuleViolation(
                    rule_id="AIML031",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="URL-based injection risk: External content fetched without sanitization before LLM processing",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_document_poisoning(self, node: ast.Call) -> None:
        """AIML032: Detect document poisoning (PDF, DOCX injection)."""
        if not self.has_llm_framework:
            return
        
        # Check for document parsing libraries
        if isinstance(node.func, ast.Attribute):
            doc_parsers = ["extract_text", "read_pdf", "parse_docx", "load_document", "parse_document"]
            if node.func.attr in doc_parsers:
                violation = RuleViolation(
                    rule_id="AIML032",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Document poisoning risk: Document content parsed without validation before LLM processing",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_image_injection(self, node: ast.Call) -> None:
        """AIML033: Detect image-based prompt injection (OCR manipulation)."""
        if not self.has_llm_framework:
            return
        
        # Check for OCR/image processing
        if isinstance(node.func, ast.Attribute):
            image_processors = ["image_to_text", "ocr", "read_text", "extract_text_from_image", "vision"]
            if node.func.attr in image_processors:
                violation = RuleViolation(
                    rule_id="AIML033",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Image-based injection risk: OCR/image text extracted without validation before LLM processing",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_api_response_injection(self, node: ast.Call) -> None:
        """AIML034: Detect API response injection (3rd party data)."""
        if not self.has_llm_framework:
            return
        
        # Check for API response parsing (json(), .text, etc.)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["json", "text", "content"]:
                # Check if this is from a response object
                if isinstance(node.func.value, ast.Name):
                    if "response" in node.func.value.id.lower() or "resp" in node.func.value.id.lower():
                        violation = RuleViolation(
                            rule_id="AIML034",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="API response injection risk: Third-party API data used without sanitization",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM01",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_database_injection(self, node: ast.Call) -> None:
        """AIML035: Detect database content injection."""
        if not self.has_llm_framework:
            return
        
        # Check for database query executions
        if isinstance(node.func, ast.Attribute):
            db_methods = ["execute", "fetchall", "fetchone", "query", "find", "find_one"]
            if node.func.attr in db_methods:
                violation = RuleViolation(
                    rule_id="AIML035",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Database injection risk: Database content used without validation in LLM prompts",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_file_upload_injection(self, node: ast.Call) -> None:
        """AIML036: Detect file upload injection vectors."""
        if not self.has_llm_framework:
            return
        
        # Check for file read/upload operations
        if isinstance(node.func, ast.Attribute):
            file_ops = ["read", "read_text", "readlines", "load", "upload"]
            if node.func.attr in file_ops:
                # Check if this is a file operation
                if isinstance(node.func.value, ast.Name):
                    if "file" in node.func.value.id.lower() or "upload" in node.func.value.id.lower():
                        violation = RuleViolation(
                            rule_id="AIML036",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="File upload injection risk: Uploaded file content used without validation",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM01",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_email_injection(self, node: ast.Call) -> None:
        """AIML037: Detect email content injection."""
        if not self.has_llm_framework:
            return
        
        # Check for email parsing
        if isinstance(node.func, ast.Attribute):
            email_methods = ["get_body", "get_content", "parse_email", "read_email"]
            if node.func.attr in email_methods:
                violation = RuleViolation(
                    rule_id="AIML037",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Email injection risk: Email content used without sanitization in LLM prompts",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_social_scraping_injection(self, node: ast.Call) -> None:
        """AIML038: Detect social media scraping injection."""
        if not self.has_llm_framework:
            return
        
        # Check for social media APIs
        if isinstance(node.func, ast.Attribute):
            social_methods = ["get_tweets", "get_posts", "scrape", "fetch_timeline", "get_comments"]
            if node.func.attr in social_methods:
                violation = RuleViolation(
                    rule_id="AIML038",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Social scraping injection risk: Social media content used without validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_rag_poisoning(self, node: ast.Call) -> None:
        """AIML039: Detect RAG poisoning (retrieval augmented generation)."""
        if not self.has_llm_framework:
            return
        
        # Check for RAG operations
        if isinstance(node.func, ast.Attribute):
            rag_methods = ["retrieve", "search", "query", "get_context", "get_relevant_docs"]
            if node.func.attr in rag_methods:
                # Check if this is a vector/document search
                if isinstance(node.func.value, ast.Name):
                    if any(keyword in node.func.value.id.lower() for keyword in ["vector", "index", "retriev", "rag", "embed"]):
                        violation = RuleViolation(
                            rule_id="AIML039",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="RAG poisoning risk: Retrieved content used without validation in prompts",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM01",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_vector_db_injection(self, node: ast.Call) -> None:
        """AIML040: Detect vector database injection."""
        if not self.has_llm_framework:
            return
        
        # Check for vector database operations
        if isinstance(node.func, ast.Attribute):
            vector_methods = ["similarity_search", "query", "search", "find_similar"]
            if node.func.attr in vector_methods:
                violation = RuleViolation(
                    rule_id="AIML040",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Vector database injection risk: Vector search results used without validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_knowledge_base_tampering(self, node: ast.Call) -> None:
        """AIML041: Detect knowledge base tampering."""
        if not self.has_llm_framework:
            return
        
        # Check for knowledge base access
        if isinstance(node.func, ast.Attribute):
            kb_methods = ["get_knowledge", "query_kb", "search_kb", "get_facts"]
            if node.func.attr in kb_methods:
                violation = RuleViolation(
                    rule_id="AIML041",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Knowledge base tampering risk: KB content used without integrity verification",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_citation_manipulation(self, node: ast.Call) -> None:
        """AIML042: Detect citation manipulation."""
        if not self.has_llm_framework:
            return
        
        # Check for citation/reference extraction
        if isinstance(node.func, ast.Attribute):
            citation_methods = ["get_citations", "get_references", "get_sources", "extract_citations"]
            if node.func.attr in citation_methods:
                violation = RuleViolation(
                    rule_id="AIML042",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Citation manipulation risk: Citation data used without verification",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_search_poisoning(self, node: ast.Call) -> None:
        """AIML043: Detect search result poisoning."""
        if not self.has_llm_framework:
            return
        
        # Check for web/search results
        if isinstance(node.func, ast.Attribute):
            search_methods = ["search", "google_search", "web_search", "get_results"]
            if node.func.attr in search_methods:
                violation = RuleViolation(
                    rule_id="AIML043",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Search result poisoning risk: Search results used without validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_user_profile_injection(self, node: ast.Call) -> None:
        """AIML044: Detect user profile injection."""
        if not self.has_llm_framework:
            return
        
        # Check for user profile access
        if isinstance(node.func, ast.Attribute):
            profile_methods = ["get_profile", "get_user_data", "get_user_info", "load_profile"]
            if node.func.attr in profile_methods:
                violation = RuleViolation(
                    rule_id="AIML044",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="User profile injection risk: User-controlled profile data used in prompts",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_conversation_history_injection(self, node: ast.Call) -> None:
        """AIML045: Detect conversation history injection."""
        if not self.has_llm_framework:
            return
        
        # Check for conversation history access
        if isinstance(node.func, ast.Attribute):
            history_methods = ["get_history", "load_history", "get_messages", "get_conversation"]
            if node.func.attr in history_methods:
                violation = RuleViolation(
                    rule_id="AIML045",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Conversation history injection risk: Chat history used without sanitization",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    # Phase 1.1.3: LLM API Security (15 checks - AIML046-AIML060)
    
    def _check_missing_rate_limiting(self, node: ast.Call) -> None:
        """AIML046: Detect missing rate limiting on LLM API calls."""
        if not self.has_llm_framework:
            return
        
        # Check for LLM API calls without rate limiting
        llm_api_calls = [
            "create", "completion", "chat", "complete",
            "ChatCompletion", "Completion", "generate"
        ]
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in llm_api_calls:
                # Simple heuristic: Check if there's no rate limiting decorator or call
                # This is a simplified check - in reality, would need more context
                violation = RuleViolation(
                    rule_id="AIML046",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Missing rate limiting on LLM API call - potential DoS risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM04",
                    cwe_id="CWE-770",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_unvalidated_llm_parameters(self, node: ast.Call) -> None:
        """AIML047: Detect unvalidated temperature/top_p parameters."""
        if not self.has_llm_framework:
            return
        
        # Check for temperature and top_p parameters that could be manipulated
        for keyword in node.keywords:
            if keyword.arg in ["temperature", "top_p", "top_k"]:
                # Check if value comes from user input (not a constant)
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML047",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message=f"Unvalidated {keyword.arg} parameter - could enable model manipulation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_max_tokens_manipulation(self, node: ast.Call) -> None:
        """AIML048: Detect max_tokens manipulation (DoS)."""
        if not self.has_llm_framework:
            return
        
        # Check for max_tokens parameter
        for keyword in node.keywords:
            if keyword.arg in ["max_tokens", "max_length", "max_new_tokens"]:
                # Check if value is not validated or comes from user input
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML048",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Max tokens parameter from user input - DoS risk from excessive token generation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM04",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_streaming_response_injection(self, node: ast.Call) -> None:
        """AIML049: Detect streaming response injection."""
        if not self.has_llm_framework:
            return
        
        # Check for streaming API calls
        for keyword in node.keywords:
            if keyword.arg == "stream":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    violation = RuleViolation(
                        rule_id="AIML049",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Streaming response without validation - injection risk in streamed chunks",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_function_calling_injection(self, node: ast.Call) -> None:
        """AIML050: Detect function calling injection."""
        if not self.has_llm_framework:
            return
        
        # Check for function calling parameters
        for keyword in node.keywords:
            if keyword.arg in ["functions", "tools", "function_call"]:
                violation = RuleViolation(
                    rule_id="AIML050",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Function calling enabled - validate function parameters to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM01",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tool_use_tampering(self, node: ast.Call) -> None:
        """AIML051: Detect tool use parameter tampering."""
        if not self.has_llm_framework:
            return
        
        # Check for tool use configurations
        for keyword in node.keywords:
            if keyword.arg in ["tool_choice", "tools"]:
                # Check if tool parameters could be user-controlled
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML051",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Tool use parameters from user input - tampering risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_system_message_manipulation(self, node: ast.Call) -> None:
        """AIML052: Detect system message manipulation via API."""
        if not self.has_llm_framework:
            return
        
        # Check for messages parameter with system role
        for keyword in node.keywords:
            if keyword.arg == "messages":
                # Check if it's a list/dict that could contain user-controlled system messages
                if isinstance(keyword.value, (ast.List, ast.Dict, ast.Name)):
                    violation = RuleViolation(
                        rule_id="AIML052",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="System message construction - ensure user input cannot modify system role",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_model_selection_bypass(self, node: ast.Call) -> None:
        """AIML053: Detect model selection bypass."""
        if not self.has_llm_framework:
            return
        
        # Check for model parameter that could be user-controlled
        for keyword in node.keywords:
            if keyword.arg in ["model", "engine", "model_name"]:
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML053",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Model selection from user input - bypass risk and cost implications",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_api_key_exposure(self, node: ast.Call) -> None:
        """AIML054: Detect API key exposure in client code."""
        if not self.has_llm_framework:
            return
        
        # Check for hardcoded API keys
        for keyword in node.keywords:
            if keyword.arg in ["api_key", "api_token", "auth_token", "key"]:
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    # Check if it looks like an API key (common patterns)
                    key_value = keyword.value.value
                    if len(key_value) > 10 and not key_value.startswith("$"):  # Not env var
                        violation = RuleViolation(
                            rule_id="AIML054",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.CRITICAL,
                            message="API key hardcoded in client code - use environment variables instead",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM10",
                            cwe_id="CWE-798",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_hardcoded_model_names(self, node: ast.Call) -> None:
        """AIML055: Detect hardcoded model names (version lock-in)."""
        if not self.has_llm_framework:
            return
        
        # Check for hardcoded model names without version pinning
        for keyword in node.keywords:
            if keyword.arg in ["model", "engine"]:
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    model_name = keyword.value.value
                    # Check if it's a model name without version
                    common_models = ["gpt-3.5-turbo", "gpt-4", "claude", "llama"]
                    if any(m in model_name.lower() for m in common_models):
                        violation = RuleViolation(
                            rule_id="AIML055",
                            category=RuleCategory.CONVENTION,
                            severity=RuleSeverity.LOW,
                            message="Hardcoded model name - consider using configuration for flexibility",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM04",
                            cwe_id="CWE-1188",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_missing_timeout(self, node: ast.Call) -> None:
        """AIML056: Detect missing timeout configurations."""
        if not self.has_llm_framework:
            return
        
        # Check for LLM API calls
        llm_api_calls = [
            "create", "completion", "chat", "complete",
            "ChatCompletion", "Completion", "generate"
        ]
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in llm_api_calls:
                # Check if timeout is specified
                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    violation = RuleViolation(
                        rule_id="AIML056",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Missing timeout on LLM API call - DoS risk from hanging requests",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM04",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_unhandled_api_errors(self, node: ast.Call) -> None:
        """AIML057: Detect unhandled API errors (info disclosure)."""
        if not self.has_llm_framework:
            return
        
        # This check would ideally look at try/except blocks around API calls
        # For now, we flag API calls that might need error handling
        llm_api_calls = [
            "create", "completion", "chat", "complete",
            "ChatCompletion", "Completion", "generate"
        ]
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in llm_api_calls:
                # Simple heuristic: flag for manual review
                violation = RuleViolation(
                    rule_id="AIML057",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="LLM API call - ensure error handling prevents information disclosure",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM04",
                    cwe_id="CWE-209",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_token_counting_bypass(self, node: ast.Call) -> None:
        """AIML058: Detect token counting bypass."""
        if not self.has_llm_framework:
            return
        
        # Check for API calls without token counting
        llm_api_calls = [
            "create", "completion", "chat", "complete",
            "ChatCompletion", "Completion", "generate"
        ]
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in llm_api_calls:
                # Simple heuristic: warn about token counting
                violation = RuleViolation(
                    rule_id="AIML058",
                    category=RuleCategory.CONVENTION,
                    severity=RuleSeverity.LOW,
                    message="LLM API call - implement token counting to prevent context overflow",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM04",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_cost_overflow(self, node: ast.Call) -> None:
        """AIML059: Detect cost overflow attacks."""
        if not self.has_llm_framework:
            return
        
        # Check for expensive operations without cost limits
        for keyword in node.keywords:
            if keyword.arg in ["n", "num_completions", "best_of"]:
                # Check if value could be user-controlled
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML059",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Completion count from user input - cost overflow risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM04",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_conversation_state_injection(self, node: ast.Call) -> None:
        """AIML060: Detect multi-turn conversation state injection."""
        if not self.has_llm_framework:
            return
        
        # Check for state management in multi-turn conversations
        state_keywords = ["session_id", "conversation_id", "state", "context"]
        
        for keyword in node.keywords:
            if keyword.arg in state_keywords:
                # Check if state could be user-controlled
                if not isinstance(keyword.value, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML060",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Conversation state from user input - injection risk in multi-turn interactions",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM01",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    # Phase 1.1.4: Output Validation & Filtering (10 checks - AIML061-AIML070)
    
    def _check_missing_output_sanitization(self, node: ast.Call) -> None:
        """AIML061: Detect missing output sanitization on LLM responses."""
        if not self.has_llm_framework:
            return
        
        # Check for LLM API calls that produce responses
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # Check for common LLM response methods
        llm_response_methods = ["create", "complete", "chat", "generate", "invoke", "call"]
        if any(method in func_name.lower() for method in llm_response_methods):
            # Flag if output is not being sanitized (heuristic check)
            violation = RuleViolation(
                rule_id="AIML061",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Missing output sanitization - ensure LLM response is validated before use",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="LLM02",
                cwe_id="CWE-20",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_code_execution_in_response(self, node: ast.Call) -> None:
        """AIML062: Detect code execution risks in LLM responses."""
        if not self.has_llm_framework:
            return
        
        # Check for dangerous execution functions that might use LLM output
        dangerous_funcs = ["exec", "eval", "compile", "__import__"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in dangerous_funcs:
            # Check if any argument looks like it could come from LLM
            for arg in node.args:
                if isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript)):
                    violation = RuleViolation(
                        rule_id="AIML062",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Code execution on LLM response - extreme arbitrary code execution risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_sql_injection_in_generated(self, node: ast.Call) -> None:
        """AIML063: Detect SQL injection risks via LLM-generated queries."""
        if not self.has_llm_framework:
            return
        
        # Check for SQL execution functions
        sql_funcs = ["execute", "executemany", "raw", "exec_driver_sql"]
        
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in sql_funcs:
            # Check if argument could be from LLM-generated content
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML063",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="SQL execution with dynamic query - SQL injection risk if using LLM-generated content",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-89",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_xss_in_generated_html(self, node: ast.Call) -> None:
        """AIML064: Detect XSS risks via LLM-generated HTML."""
        if not self.has_llm_framework:
            return
        
        # Check for HTML rendering functions
        html_funcs = ["render", "render_template", "render_to_string", "mark_safe", "Markup"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if any(html_func in func_name for html_func in html_funcs):
            # Check if rendering dynamic content
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML064",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="HTML rendering with dynamic content - XSS risk if using LLM-generated HTML",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-79",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_command_injection_in_generated(self, node: ast.Call) -> None:
        """AIML065: Detect command injection risks via LLM-generated shell scripts."""
        if not self.has_llm_framework:
            return
        
        # Check for shell command execution
        shell_funcs = ["system", "popen", "run", "call", "check_output", "Popen"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in shell_funcs:
            # Check if using dynamic commands
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML065",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Shell command with dynamic input - command injection risk if using LLM-generated scripts",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-78",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_path_traversal_in_generated(self, node: ast.Call) -> None:
        """AIML066: Detect path traversal risks in LLM-generated file paths."""
        if not self.has_llm_framework:
            return
        
        # Check for file operations
        file_funcs = ["open", "read", "write", "remove", "unlink", "rmdir"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in file_funcs:
            # Check if using dynamic file paths
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML066",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="File operation with dynamic path - path traversal risk if using LLM-generated paths",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-22",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_arbitrary_file_access_in_generated(self, node: ast.Call) -> None:
        """AIML067: Detect arbitrary file access risks via LLM-generated code."""
        if not self.has_llm_framework:
            return
        
        # Check for file system access patterns
        import_funcs = ["__import__", "importlib.import_module"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_str = ""
            if hasattr(node.func.value, 'id'):
                func_str = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_str = node.func.attr
            func_name = func_str
        
        if any(imp in func_name for imp in import_funcs):
            # Check if importing dynamic modules
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML067",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Dynamic module import - arbitrary file access risk if using LLM-generated code",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_sensitive_data_leakage(self, node: ast.Call) -> None:
        """AIML068: Detect sensitive data leakage in LLM responses."""
        if not self.has_llm_framework:
            return
        
        # Check for logging or output of LLM responses
        log_funcs = ["print", "log", "debug", "info", "warning", "error", "write"]
        
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        
        if func_name in log_funcs:
            # Check if logging dynamic content that could be LLM response
            for arg in node.args:
                if isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript)):
                    # Look for response-like variable names
                    var_name = ""
                    if isinstance(arg, ast.Name):
                        var_name = arg.id
                    
                    if any(term in var_name.lower() for term in ["response", "completion", "result", "output", "answer"]):
                        violation = RuleViolation(
                            rule_id="AIML068",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Logging LLM response - sensitive data leakage risk",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="LLM06",
                            cwe_id="CWE-532",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_pii_disclosure(self, node: ast.Call) -> None:
        """AIML069: Detect PII disclosure risk from training data."""
        if not self.has_llm_framework:
            return
        
        # Check for LLM API calls that might expose training data
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # Check for completion/chat calls
        llm_funcs = ["create", "complete", "chat", "generate"]
        if any(func in func_name.lower() for func in llm_funcs):
            # Check for high temperature (more likely to leak training data)
            for keyword in node.keywords:
                if keyword.arg == "temperature":
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value > 1.5:
                            violation = RuleViolation(
                                rule_id="AIML069",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.MEDIUM,
                                message="High temperature setting - increased PII disclosure risk from training data",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.SAFE,
                                fix_data=None,
                                owasp_id="LLM06",
                                cwe_id="CWE-359",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
    
    def _check_copyright_violation_risk(self, node: ast.Call) -> None:
        """AIML070: Detect copyright violation risks from memorized content."""
        if not self.has_llm_framework:
            return
        
        # Check for LLM API calls that might generate copyrighted content
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        
        # Check for completion/chat calls with long outputs
        llm_funcs = ["create", "complete", "chat", "generate"]
        if any(func in func_name.lower() for func in llm_funcs):
            # Check for high max_tokens (more likely to generate long copyrighted text)
            for keyword in node.keywords:
                if keyword.arg in ["max_tokens", "max_length"]:
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value > 2000:
                            violation = RuleViolation(
                                rule_id="AIML070",
                                category=RuleCategory.CONVENTION,
                                severity=RuleSeverity.LOW,
                                message="High max_tokens setting - copyright violation risk from memorized content",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.MANUAL,
                                fix_data=None,
                                owasp_id="LLM06",
                                cwe_id="CWE-1059",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
    
    # Phase 1.2: Model Serialization & Loading (40 checks)
    # Phase 1.2.1: PyTorch Model Security (15 checks - AIML071-AIML085)
    
    def _check_torch_load_unsafe(self, node: ast.Call) -> None:
        """AIML071: Detect torch.load() without weights_only=True."""
        if not self.has_pytorch:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            # Check if this is torch.load
            if hasattr(node.func.value, 'id') and node.func.value.id == "torch":
                # Check for weights_only parameter
                has_weights_only = any(
                    kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                
                if not has_weights_only:
                    violation = RuleViolation(
                        rule_id="AIML071",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="torch.load() without weights_only=True - arbitrary code execution risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-502",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_torch_pickle_unsafe(self, node: ast.Call) -> None:
        """AIML072: Detect unsafe pickle in torch.save/load."""
        if not self.has_pytorch:
            return
        
        # Check for pickle.load with torch models
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["save", "load"]:
            if hasattr(node.func.value, 'id') and node.func.value.id in ["torch", "pickle"]:
                violation = RuleViolation(
                    rule_id="AIML072",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Unsafe pickle usage with PyTorch - use safetensors or weights_only=True",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-502",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_missing_model_integrity(self, node: ast.Call) -> None:
        """AIML073: Detect missing model integrity verification."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for model loading without checksum verification
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load", "load_model", "from_pretrained"]:
            # Look for missing hash/checksum parameters
            has_verification = any(
                kw.arg in ["sha256", "checksum", "hash", "revision", "etag"]
                for kw in node.keywords
            )
            
            if not has_verification:
                violation = RuleViolation(
                    rule_id="AIML073",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model loading without integrity verification - use checksums or revisions",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-494",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_untrusted_model_url(self, node: ast.Call) -> None:
        """AIML074: Detect untrusted model URL loading."""
        if not (self.has_pytorch or self.has_tensorflow or self.has_transformers):
            return
        
        # Check for URL-based model loading
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith(("http://", "https://", "ftp://")):
                    violation = RuleViolation(
                        rule_id="AIML074",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Loading model from URL - supply chain attack risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-494",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_state_dict_poisoning(self, node: ast.Call) -> None:
        """AIML075: Detect model poisoning in state_dict."""
        if not self.has_pytorch:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load_state_dict":
            violation = RuleViolation(
                rule_id="AIML075",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="load_state_dict() - validate state dict to prevent model poisoning",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_custom_module_injection(self, node: ast.Call) -> None:
        """AIML076: Detect custom layer/module injection."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for custom modules/layers being loaded
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["register_module", "add_module", "register_buffer"]:
            violation = RuleViolation(
                rule_id="AIML076",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Custom module registration - validate to prevent code injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_torch_jit_unsafe(self, node: ast.Call) -> None:
        """AIML077: Detect unsafe torch.jit.load()."""
        if not self.has_pytorch:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            # Check if this is torch.jit.load
            if (hasattr(node.func.value, 'attr') and node.func.value.attr == "jit" and
                hasattr(node.func.value.value, 'id') and node.func.value.value.id == "torch"):
                violation = RuleViolation(
                    rule_id="AIML077",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="torch.jit.load() - arbitrary code execution risk via TorchScript",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-502",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_torchscript_deserialization(self, node: ast.Call) -> None:
        """AIML078: Detect TorchScript deserialization risks."""
        if not self.has_pytorch:
            return
        
        # Check for TorchScript operations
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["script", "trace", "load"]:
            if hasattr(node.func.value, 'attr') and node.func.value.attr == "jit":
                violation = RuleViolation(
                    rule_id="AIML078",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="TorchScript deserialization - validate input to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-502",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_onnx_tampering(self, node: ast.Call) -> None:
        """AIML079: Detect ONNX model tampering."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for ONNX model loading
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load", "load_model"]:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.endswith(".onnx"):
                        violation = RuleViolation(
                            rule_id="AIML079",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="ONNX model loading - verify model integrity to prevent tampering",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-494",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_model_metadata_injection(self, node: ast.Call) -> None:
        """AIML080: Detect model metadata injection."""
        if not (self.has_pytorch or self.has_tensorflow or self.has_transformers):
            return
        
        # Check for metadata loading
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load_config", "config", "metadata"]:
            violation = RuleViolation(
                rule_id="AIML080",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Model metadata loading - validate to prevent injection attacks",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_missing_gpu_limits(self, node: ast.Call) -> None:
        """AIML081: Detect missing GPU memory limits."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for GPU operations without memory limits
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["cuda", "to"]:
            # Check if device is being set to GPU without memory limits
            has_memory_limit = any(
                kw.arg in ["max_memory", "device_map", "max_split_size_mb"]
                for kw in node.keywords
            )
            
            if not has_memory_limit:
                violation = RuleViolation(
                    rule_id="AIML081",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="GPU usage without memory limits - resource exhaustion risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML09",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tensor_size_attacks(self, node: ast.Call) -> None:
        """AIML082: Detect tensor size attacks (memory exhaustion)."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for tensor operations with user-controlled sizes
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["zeros", "ones", "empty", "randn", "rand"]:
            # Check if size is from user input (not a constant)
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    violation = RuleViolation(
                        rule_id="AIML082",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Tensor creation with dynamic size - memory exhaustion risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML09",
                        cwe_id="CWE-400",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_quantization_vulnerabilities(self, node: ast.Call) -> None:
        """AIML083: Detect quantization vulnerabilities."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for quantization operations
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["quantize", "quantize_dynamic", "quantize_per_tensor"]:
            violation = RuleViolation(
                rule_id="AIML083",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="Model quantization - validate to prevent accuracy degradation attacks",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_mixed_precision_attacks(self, node: ast.Call) -> None:
        """AIML084: Detect mixed precision attacks."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for mixed precision training/inference
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["autocast", "amp"]:
            violation = RuleViolation(
                rule_id="AIML084",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="Mixed precision mode - validate precision settings to prevent attacks",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_model_zoo_trust(self, node: ast.Call) -> None:
        """AIML085: Detect model zoo trust verification."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
        
        # Check for model zoo downloads
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load_state_dict_from_url", "hub.load"]:
            violation = RuleViolation(
                rule_id="AIML085",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Model zoo download - verify model source and integrity",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-494",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    # Phase 1.2.2: TensorFlow/Keras Security (15 checks - AIML086-AIML100)
    
    def _check_savedmodel_unsafe(self, node: ast.Call) -> None:
        """AIML086: Detect SavedModel arbitrary code execution."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load_model", "load"]:
            # Check for TensorFlow SavedModel loading
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    violation = RuleViolation(
                        rule_id="AIML086",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="TensorFlow SavedModel loading - arbitrary code execution risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-502",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break
    
    def _check_hdf5_deserialization(self, node: ast.Call) -> None:
        """AIML087: Detect HDF5 deserialization attacks."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
            # Check for .h5 or .hdf5 files
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.endswith((".h5", ".hdf5", ".keras")):
                        violation = RuleViolation(
                            rule_id="AIML087",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="HDF5/Keras model loading - deserialization attack risk",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-502",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_keras_custom_object_injection(self, node: ast.Call) -> None:
        """AIML088: Detect custom object injection in model.load."""
        if not self.has_tensorflow:
            return
        
        # Check for custom_objects parameter
        for keyword in node.keywords:
            if keyword.arg == "custom_objects":
                violation = RuleViolation(
                    rule_id="AIML088",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Custom objects in Keras model - validate to prevent code injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tf_hub_trust(self, node: ast.Call) -> None:
        """AIML089: Detect TensorFlow Hub model trust."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load", "KerasLayer"]:
            # Check if loading from TF Hub
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if "tfhub.dev" in arg.value or "hub" in arg.value:
                        violation = RuleViolation(
                            rule_id="AIML089",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="TensorFlow Hub model loading - verify model source and integrity",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-494",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_graph_execution_injection(self, node: ast.Call) -> None:
        """AIML090: Detect graph execution injection."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["graph", "GraphDef", "import_graph_def"]:
            violation = RuleViolation(
                rule_id="AIML090",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="TensorFlow graph operation - validate to prevent injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_checkpoint_poisoning(self, node: ast.Call) -> None:
        """AIML091: Detect checkpoint poisoning."""
        if not (self.has_tensorflow or self.has_pytorch):
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["restore", "load_checkpoint", "from_checkpoint"]:
            violation = RuleViolation(
                rule_id="AIML091",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Checkpoint loading - verify integrity to prevent poisoning",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_keras_lambda_injection(self, node: ast.Call) -> None:
        """AIML092: Detect Keras Lambda layer code injection."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Name) and node.func.id == "Lambda":
            violation = RuleViolation(
                rule_id="AIML092",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Keras Lambda layer - code injection risk with untrusted input",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_custom_metric_tampering(self, node: ast.Call) -> None:
        """AIML093: Detect custom metric/loss function tampering."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["compile"]:
            # Check for custom metrics or loss functions
            for keyword in node.keywords:
                if keyword.arg in ["metrics", "loss"]:
                    if not isinstance(keyword.value, (ast.Constant, ast.List)):
                        violation = RuleViolation(
                            rule_id="AIML093",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Custom metrics/loss functions - validate to prevent tampering",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-345",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_tflite_manipulation(self, node: ast.Call) -> None:
        """AIML094: Detect TF Lite model manipulation."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["Interpreter", "load_model"]:
            # Check for .tflite files
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.endswith(".tflite"):
                        violation = RuleViolation(
                            rule_id="AIML094",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="TF Lite model loading - verify integrity to prevent manipulation",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-494",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_tensorboard_injection(self, node: ast.Call) -> None:
        """AIML095: Detect TensorBoard log injection."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["SummaryWriter", "FileWriter"]:
            violation = RuleViolation(
                rule_id="AIML095",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="TensorBoard logging - sanitize data to prevent log injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-117",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_tf_serving_vulnerabilities(self, node: ast.Call) -> None:
        """AIML096: Detect model serving vulnerabilities (TF Serving)."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["export_saved_model", "export"]:
            violation = RuleViolation(
                rule_id="AIML096",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Model export for serving - ensure proper access controls",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML09",
                cwe_id="CWE-285",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_graphdef_manipulation(self, node: ast.Call) -> None:
        """AIML097: Detect GraphDef manipulation."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["ParseFromString", "import_graph_def"]:
            violation = RuleViolation(
                rule_id="AIML097",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="GraphDef parsing - validate to prevent manipulation",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-502",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_operation_injection(self, node: ast.Call) -> None:
        """AIML098: Detect operation injection attacks."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["add_op", "register_op"]:
            violation = RuleViolation(
                rule_id="AIML098",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Operation registration - validate to prevent injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_resource_exhaustion_model(self, node: ast.Call) -> None:
        """AIML099: Detect resource exhaustion via model architecture."""
        if not (self.has_tensorflow or self.has_pytorch):
            return
        
        # Check for operations that could cause resource exhaustion
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["Sequential", "Model"]:
            violation = RuleViolation(
                rule_id="AIML099",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Model architecture creation - validate complexity to prevent DoS",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML09",
                cwe_id="CWE-400",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_tfrecord_poisoning(self, node: ast.Call) -> None:
        """AIML100: Detect TFRecord poisoning."""
        if not self.has_tensorflow:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["TFRecordReader", "TFRecordDataset"]:
            violation = RuleViolation(
                rule_id="AIML100",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="TFRecord loading - validate data to prevent poisoning",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    # Phase 1.2.3: Hugging Face & Transformers (10 checks - AIML101-AIML110)
    
    def _check_from_pretrained_trust(self, node: ast.Call) -> None:
        """AIML101: Detect from_pretrained() trust issues."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_pretrained":
            # Check for trust_remote_code parameter
            has_trust_param = any(
                kw.arg == "trust_remote_code" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                for kw in node.keywords
            )
            
            if not has_trust_param:
                violation = RuleViolation(
                    rule_id="AIML101",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="from_pretrained() without trust_remote_code=False - arbitrary code execution risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_card_credentials(self, node: ast.Call) -> None:
        """AIML102: Detect model card credential leakage."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["push_to_hub", "create_model_card"]:
            # Check for token parameter
            for keyword in node.keywords:
                if keyword.arg in ["token", "use_auth_token"]:
                    if isinstance(keyword.value, ast.Constant):
                        violation = RuleViolation(
                            rule_id="AIML102",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="Hardcoded token in model card - credential leakage risk",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-798",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
                        break
    
    def _check_tokenizer_vulnerabilities(self, node: ast.Call) -> None:
        """AIML103: Detect tokenizer vulnerabilities."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["tokenize", "encode", "batch_encode"]:
            # Check for truncation/max_length parameters
            has_limits = any(
                kw.arg in ["max_length", "truncation"]
                for kw in node.keywords
            )
            
            if not has_limits:
                violation = RuleViolation(
                    rule_id="AIML103",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Tokenizer without limits - DoS risk from long inputs",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML09",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_pipeline_injection(self, node: ast.Call) -> None:
        """AIML104: Detect pipeline injection attacks."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Name) and node.func.id == "pipeline":
            violation = RuleViolation(
                rule_id="AIML104",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Transformers pipeline - validate task and model to prevent injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-94",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_hf_dataset_poisoning(self, node: ast.Call) -> None:
        """AIML105: Detect dataset poisoning (Hugging Face Datasets)."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["load_dataset", "load_from_disk"]:
            violation = RuleViolation(
                rule_id="AIML105",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Dataset loading - validate source to prevent poisoning",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_missing_model_signature(self, node: ast.Call) -> None:
        """AIML106: Detect missing model signature verification."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_pretrained":
            # Check for revision or commit hash
            has_version = any(
                kw.arg in ["revision", "commit_hash"]
                for kw in node.keywords
            )
            
            if not has_version:
                violation = RuleViolation(
                    rule_id="AIML106",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model loading without version pinning - supply chain attack risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-494",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_arbitrary_file_in_config(self, node: ast.Call) -> None:
        """AIML107: Detect arbitrary file loading in model config."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["from_json_file", "from_dict"]:
            violation = RuleViolation(
                rule_id="AIML107",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.HIGH,
                message="Config loading from file - arbitrary file access risk",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-22",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_space_app_injection(self, node: ast.Call) -> None:
        """AIML108: Detect Space app injection (Gradio/Streamlit)."""
        if not self.has_transformers:
            return
        
        # Check for Gradio/Streamlit interfaces
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["Interface", "launch"]:
            violation = RuleViolation(
                rule_id="AIML108",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Gradio/Streamlit interface - validate inputs to prevent injection",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML09",
                cwe_id="CWE-20",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_model_repo_tampering(self, node: ast.Call) -> None:
        """AIML109: Detect model repository tampering."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["clone_from", "Repository"]:
            violation = RuleViolation(
                rule_id="AIML109",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Model repository cloning - verify source to prevent tampering",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.SAFE,
                fix_data=None,
                owasp_id="ML05",
                cwe_id="CWE-494",
                source_tool="pyguard",
            )
            self.violations.append(violation)
    
    def _check_private_model_access(self, node: ast.Call) -> None:
        """AIML110: Detect private model access control."""
        if not self.has_transformers:
            return
        
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_pretrained":
            # Check for private models without proper authentication
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    # Look for model names that might be private
                    if "/" in arg.value:  # org/model format
                        has_auth = any(
                            kw.arg in ["token", "use_auth_token"]
                            for kw in node.keywords
                        )
                        
                        if not has_auth:
                            violation = RuleViolation(
                                rule_id="AIML110",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.LOW,
                                message="Model loading without authentication - consider access controls",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.MANUAL,
                                fix_data=None,
                                owasp_id="ML05",
                                cwe_id="CWE-285",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                        break

    # Phase 1.3: Training & Fine-Tuning Security (30 checks)
    # Phase 1.3.1: Training Data Security (12 checks - AIML111-AIML122)
    
    def _check_unvalidated_training_data(self, node: ast.Call) -> None:
        """AIML111: Detect unvalidated training data sources."""
        if not self.has_ml_framework:
            return
        
        # Check for data loading from URLs or files without validation
        data_loaders = ["load_dataset", "read_csv", "from_csv", "ImageFolder", "DataLoader"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in data_loaders:
                # Check if validation is mentioned anywhere
                has_validation = any(
                    kw.arg in ["trust", "verify", "validate", "safe_mode"]
                    for kw in node.keywords
                )
                
                if not has_validation:
                    violation = RuleViolation(
                        rule_id="AIML111",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Training data from unvalidated source - data poisoning risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_missing_data_sanitization(self, node: ast.Call) -> None:
        """AIML112: Detect missing data sanitization."""
        if not self.has_ml_framework:
            return
        
        # Check for text/string data loading without sanitization
        text_loaders = ["read_text", "load_dataset", "read_csv", "from_pandas"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in text_loaders:
                has_sanitization = any(
                    kw.arg in ["clean", "sanitize", "strip", "preprocess"]
                    for kw in node.keywords
                )
                
                if not has_sanitization:
                    violation = RuleViolation(
                        rule_id="AIML112",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Training data without sanitization - injection risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_pii_in_training_data(self, node: ast.Call) -> None:
        """AIML113: Detect PII leakage in training datasets."""
        if not self.has_ml_framework:
            return
        
        # Check for training with user data or sensitive sources
        sensitive_sources = ["user_data", "customers", "patients", "employees", "personal"]
        
        for arg in node.args:
            if isinstance(arg, (ast.Name, ast.Constant)):
                value = arg.id if isinstance(arg, ast.Name) else str(arg.value).lower()
                if any(source in value.lower() for source in sensitive_sources):
                    violation = RuleViolation(
                        rule_id="AIML113",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="PII in training data - privacy violation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML06",
                        cwe_id="CWE-359",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break

    def _check_copyright_infringing_data(self, node: ast.Call) -> None:
        """AIML114: Detect copyright-infringing data inclusion."""
        if not self.has_ml_framework:
            return
        
        # Check for web scraping without copyright consideration
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in ["scrape", "crawl", "fetch_web", "download"]:
                violation = RuleViolation(
                    rule_id="AIML114",
                    category=RuleCategory.CONVENTION,
                    severity=RuleSeverity.MEDIUM,
                    message="Training data may include copyrighted content - legal risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-1059",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_label_flipping_detection(self, node: ast.Call) -> None:
        """AIML115: Detect label flipping attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for training without label validation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["fit", "train", "fit_transform"]:
                has_validation = any(
                    kw.arg in ["validate_labels", "check_labels", "verify_labels"]
                    for kw in node.keywords
                )
                
                if not has_validation:
                    violation = RuleViolation(
                        rule_id="AIML115",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Training without label validation - label flipping attack risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_backdoor_in_dataset(self, node: ast.Call) -> None:
        """AIML116: Detect backdoor injection in datasets."""
        if not self.has_ml_framework:
            return
        
        # Check for dataset loading without backdoor detection
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in ["load_dataset", "ImageFolder", "DataLoader"]:
                has_detection = any(
                    kw.arg in ["scan_backdoor", "detect_triggers", "verify_clean"]
                    for kw in node.keywords
                )
                
                if not has_detection:
                    violation = RuleViolation(
                        rule_id="AIML116",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Dataset without backdoor detection - hidden trigger risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-912",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_trigger_pattern_insertion(self, node: ast.Call) -> None:
        """AIML117: Detect trigger pattern insertion."""
        if not self.has_ml_framework:
            return
        
        # Check for data augmentation without trigger validation
        augmentation_funcs = ["RandomCrop", "RandomFlip", "ColorJitter", "augment", "transform"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in augmentation_funcs:
                violation = RuleViolation(
                    rule_id="AIML117",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Data augmentation without validation - trigger pattern risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_data_augmentation_attacks(self, node: ast.Call) -> None:
        """AIML118: Detect data augmentation attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for complex augmentation pipelines
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "Compose" in func_name or "Pipeline" in func_name:
                violation = RuleViolation(
                    rule_id="AIML118",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Data augmentation - validate transformations to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_synthetic_data_vulnerabilities(self, node: ast.Call) -> None:
        """AIML119: Detect synthetic data vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for synthetic data generation
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "generate" in func_name.lower() or "synthesize" in func_name.lower():
                violation = RuleViolation(
                    rule_id="AIML119",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Synthetic data generation - validate quality and safety",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_web_scraping_data_risks(self, node: ast.Call) -> None:
        """AIML120: Detect web scraping data risks."""
        if not self.has_ml_framework:
            return
        
        # Check for web scraping functions
        scraping_funcs = ["scrape", "crawl", "BeautifulSoup", "requests.get", "urllib"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if any(func in func_name for func in scraping_funcs):
                violation = RuleViolation(
                    rule_id="AIML120",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Web scraped data - validate and sanitize to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_user_generated_content_risks(self, node: ast.Call) -> None:
        """AIML121: Detect user-generated content risks."""
        if not self.has_ml_framework:
            return
        
        # Check for loading user content for training
        for arg in node.args:
            if isinstance(arg, (ast.Name, ast.Constant)):
                value = arg.id if isinstance(arg, ast.Name) else str(arg.value).lower()
                if "user" in value or "upload" in value or "submission" in value:
                    violation = RuleViolation(
                        rule_id="AIML121",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="User-generated training data - validate to prevent poisoning",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break

    def _check_missing_data_provenance(self, node: ast.Call) -> None:
        """AIML122: Detect missing data provenance tracking."""
        if not self.has_ml_framework:
            return
        
        # Check for data loading without provenance tracking
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if func_name in ["load_dataset", "read_csv", "from_csv"]:
                has_provenance = any(
                    kw.arg in ["source", "origin", "metadata", "provenance"]
                    for kw in node.keywords
                )
                
                if not has_provenance:
                    violation = RuleViolation(
                        rule_id="AIML122",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.MEDIUM,
                        message="Training data without provenance - unable to verify integrity",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-778",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    # Phase 1.3.2: Training Process Security (10 checks - AIML123-AIML132)
    
    def _check_gradient_manipulation(self, node: ast.Call) -> None:
        """AIML123: Detect gradient manipulation attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for gradient computation without validation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["backward", "grad", "gradient"]:
                violation = RuleViolation(
                    rule_id="AIML123",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Gradient computation - validate to prevent manipulation attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_learning_rate_manipulation(self, node: ast.Call) -> None:
        """AIML124: Detect learning rate manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for dynamic learning rate changes without validation
        for keyword in node.keywords:
            if keyword.arg == "lr" or keyword.arg == "learning_rate":
                if isinstance(keyword.value, ast.Name):  # Variable, not constant
                    violation = RuleViolation(
                        rule_id="AIML124",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Dynamic learning rate without validation - manipulation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
                    break

    def _check_optimizer_state_poisoning(self, node: ast.Call) -> None:
        """AIML125: Detect optimizer state poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for optimizer state loading
        if isinstance(node.func, ast.Attribute):
            if "load_state_dict" in node.func.attr and "optimizer" in self.lines[node.lineno - 1].lower():
                violation = RuleViolation(
                    rule_id="AIML125",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Optimizer state loading - verify integrity to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_checkpoint_tampering_training(self, node: ast.Call) -> None:
        """AIML126: Detect checkpoint tampering during training."""
        if not self.has_ml_framework:
            return
        
        # Check for checkpoint saving without integrity protection
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "save" in func_name and "checkpoint" in self.lines[node.lineno - 1].lower():
                has_hash = any(
                    kw.arg in ["checksum", "hash", "integrity"]
                    for kw in node.keywords
                )
                
                if not has_hash:
                    violation = RuleViolation(
                        rule_id="AIML126",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Checkpoint saving without integrity checks - tampering risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-494",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_early_stopping_bypass(self, node: ast.Call) -> None:
        """AIML127: Detect early stopping bypass."""
        if not self.has_ml_framework:
            return
        
        # Check for early stopping without validation monitoring
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "EarlyStopping" in func_name:
                violation = RuleViolation(
                    rule_id="AIML127",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Early stopping without validation monitoring - bypass risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_validation_set_poisoning(self, node: ast.Call) -> None:
        """AIML128: Detect validation set poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for validation data loading
        for keyword in node.keywords:
            if keyword.arg in ["validation_data", "val_data", "valid_data"]:
                violation = RuleViolation(
                    rule_id="AIML128",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Validation data from untrusted source - poisoning risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
                break

    def _check_tensorboard_logging_injection(self, node: ast.Call) -> None:
        """AIML129: Detect TensorBoard logging injection."""
        if not self.has_ml_framework:
            return
        
        # Check for TensorBoard logging
        if isinstance(node.func, ast.Attribute):
            if "SummaryWriter" in str(node.func) or "add_scalar" in node.func.attr:
                violation = RuleViolation(
                    rule_id="AIML129",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="TensorBoard logging - sanitize data to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-117",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_experiment_tracking_manipulation(self, node: ast.Call) -> None:
        """AIML130: Detect experiment tracking manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for experiment tracking without validation
        tracking_libs = ["mlflow", "wandb", "neptune", "comet"]
        
        if isinstance(node.func, ast.Attribute):
            if any(lib in str(node.func).lower() for lib in tracking_libs):
                if "log" in node.func.attr:
                    violation = RuleViolation(
                        rule_id="AIML130",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Experiment tracking - validate metrics to prevent manipulation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_distributed_training_node_compromise(self, node: ast.Call) -> None:
        """AIML131: Detect distributed training node compromise."""
        if not self.has_ml_framework:
            return
        
        # Check for distributed training without secure communication
        distributed_funcs = ["DistributedDataParallel", "init_process_group", "all_reduce"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if any(func in func_name for func in distributed_funcs):
                violation = RuleViolation(
                    rule_id="AIML131",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Distributed training - secure communication between nodes",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-300",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_parameter_server_vulnerabilities(self, node: ast.Call) -> None:
        """AIML132: Detect parameter server vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for parameter server usage
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "ParameterServer" in func_name or "parameter_server" in func_name:
                violation = RuleViolation(
                    rule_id="AIML132",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Parameter server - implement authentication and encryption",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Phase 1.3.3: Fine-Tuning Risks (8 checks - AIML133-AIML140)
    
    def _check_base_model_poisoning(self, node: ast.Call) -> None:
        """AIML133: Detect base model poisoning."""
        if not self.has_transformers:
            return
        
        # Check for fine-tuning from untrusted base model
        if isinstance(node.func, ast.Attribute):
            if "from_pretrained" in node.func.attr:
                has_verification = any(
                    kw.arg in ["revision", "trust_remote_code"]
                    for kw in node.keywords
                    if kw.arg == "trust_remote_code" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                )
                
                if not has_verification:
                    violation = RuleViolation(
                        rule_id="AIML133",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Fine-tuning from untrusted base model - poisoning risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_fine_tuning_data_injection(self, node: ast.Call) -> None:
        """AIML134: Detect fine-tuning data injection."""
        if not self.has_ml_framework:
            return
        
        # Check for fine-tuning with unvalidated data
        if isinstance(node.func, ast.Attribute):
            if "train" in node.func.attr or "fit" in node.func.attr:
                # Look for fine-tuning context
                line_text = self.lines[node.lineno - 1].lower()
                if "fine" in line_text or "finetune" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML134",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Fine-tuning data - validate to prevent injection attacks",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_catastrophic_forgetting_exploitation(self, node: ast.Call) -> None:
        """AIML135: Detect catastrophic forgetting exploitation."""
        if not self.has_ml_framework:
            return
        
        # Check for fine-tuning without forgetting protection
        if isinstance(node.func, ast.Attribute):
            if "train" in node.func.attr and "fine" in self.lines[node.lineno - 1].lower():
                has_protection = any(
                    kw.arg in ["preserve_weights", "elastic_weight_consolidation", "ewc"]
                    for kw in node.keywords
                )
                
                if not has_protection:
                    violation = RuleViolation(
                        rule_id="AIML135",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Fine-tuning without forgetting protection - exploitation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_peft_attacks(self, node: ast.Call) -> None:
        """AIML136: Detect PEFT attacks."""
        if not self.has_transformers:
            return
        
        # Check for PEFT without validation
        peft_funcs = ["get_peft_model", "PeftModel", "prepare_model_for_kbit_training"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if any(func in func_name for func in peft_funcs):
                violation = RuleViolation(
                    rule_id="AIML136",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="PEFT without validation - parameter tampering risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_lora_poisoning(self, node: ast.Call) -> None:
        """AIML137: Detect LoRA poisoning."""
        if not self.has_transformers:
            return
        
        # Check for LoRA adapter loading
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "LoraConfig" in func_name or "lora" in func_name.lower():
                violation = RuleViolation(
                    rule_id="AIML137",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="LoRA adapter - verify source to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_adapter_injection(self, node: ast.Call) -> None:
        """AIML138: Detect adapter injection."""
        if not self.has_transformers:
            return
        
        # Check for adapter loading
        adapter_funcs = ["add_adapter", "load_adapter", "set_adapter"]
        
        if isinstance(node.func, ast.Attribute):
            if any(func in node.func.attr for func in adapter_funcs):
                violation = RuleViolation(
                    rule_id="AIML138",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Adapter loading - validate to prevent malicious injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_prompt_tuning_manipulation(self, node: ast.Call) -> None:
        """AIML139: Detect prompt tuning manipulation."""
        if not self.has_transformers:
            return
        
        # Check for prompt tuning
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "PromptTuning" in func_name or "prompt_tuning" in func_name.lower():
                violation = RuleViolation(
                    rule_id="AIML139",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Prompt tuning - validate prompts to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_instruction_fine_tuning_risks(self, node: ast.Call) -> None:
        """AIML140: Detect instruction fine-tuning risks."""
        if not self.has_transformers:
            return
        
        # Check for instruction fine-tuning
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "instruction" in line_text and ("train" in line_text or "fine" in line_text):
            violation = RuleViolation(
                rule_id="AIML140",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.MEDIUM,
                message="Instruction fine-tuning - validate data to prevent jailbreaks",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="LLM01",
                cwe_id="CWE-345",
                source_tool="pyguard",
            )
            self.violations.append(violation)

    # Phase 1.4: Adversarial ML & Model Robustness (20 checks)
    # Phase 1.4.1: Adversarial Input Detection (10 checks - AIML141-AIML150)
    
    def _check_missing_adversarial_defense(self, node: ast.Call) -> None:
        """AIML141: Detect missing adversarial defense."""
        if not self.has_ml_framework:
            return
        
        # Check for model inference without adversarial defense
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward", "__call__", "infer"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                # Check for adversarial defense keywords
                has_defense = any(
                    keyword in line_text
                    for keyword in ["adversarial", "robust", "defense", "certify"]
                )
                
                if not has_defense:
                    violation = RuleViolation(
                        rule_id="AIML141",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model inference without adversarial defense - attack vulnerability",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_no_fgsm_protection(self, node: ast.Call) -> None:
        """AIML142: Detect lack of FGSM protection."""
        if not self.has_ml_framework:
            return
        
        # Check for training without FGSM adversarial examples
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["fit", "train"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "fgsm" not in line_text and "adversarial" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML142",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model vulnerable to FGSM attacks - add adversarial training",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_pgd_vulnerability(self, node: ast.Call) -> None:
        """AIML143: Detect PGD vulnerability."""
        if not self.has_ml_framework:
            return
        
        # Similar to FGSM check, looking for PGD protection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["fit", "train"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "pgd" not in line_text and "projected" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML143",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model vulnerable to PGD attacks - implement robust training",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_cw_attack_surface(self, node: ast.Call) -> None:
        """AIML144: Detect C&W attack surface."""
        if not self.has_ml_framework:
            return
        
        # Check for defense against C&W attacks
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "distillation" in func_name.lower() or "defensive" in str(node).lower():
                violation = RuleViolation(
                    rule_id="AIML144",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Model vulnerable to C&W attacks - add defensive distillation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_deepfool_susceptibility(self, node: ast.Call) -> None:
        """AIML145: Detect DeepFool susceptibility."""
        if not self.has_ml_framework:
            return
        
        # Check for perturbation validation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "predict":
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "perturbation" not in line_text and "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML145",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Model vulnerable to DeepFool attacks - validate input perturbations",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_universal_adversarial_perturbations(self, node: ast.Call) -> None:
        """AIML146: Detect universal adversarial perturbations vulnerability."""
        if not self.has_ml_framework:
            return
        
        # Check for input validation against universal perturbations
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward"]:
                violation = RuleViolation(
                    rule_id="AIML146",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Model vulnerable to universal perturbations - add input validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_black_box_attack_vulnerability(self, node: ast.Call) -> None:
        """AIML147: Detect black-box attack vulnerability."""
        if not self.has_ml_framework:
            return
        
        # Check for API endpoints exposing inference
        if isinstance(node.func, ast.Attribute):
            if "api" in str(node.func).lower() and "predict" in node.func.attr:
                violation = RuleViolation(
                    rule_id="AIML147",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model API exposes inference - black-box attack risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-200",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_transfer_attack_risks(self, node: ast.Call) -> None:
        """AIML148: Detect transfer attack risks."""
        if not self.has_ml_framework:
            return
        
        # Check for models similar to public architectures
        public_archs = ["resnet", "vgg", "inception", "mobilenet", "efficientnet"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = str(node.func).lower()
            
            if any(arch in func_name for arch in public_archs):
                violation = RuleViolation(
                    rule_id="AIML148",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model architecture similar to public models - transfer attack risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_physical_adversarial_examples(self, node: ast.Call) -> None:
        """AIML149: Detect physical adversarial examples vulnerability."""
        if not self.has_ml_framework:
            return
        
        # Check for vision models without physical robustness
        vision_funcs = ["detect", "classify", "segment", "recognize"]
        
        if isinstance(node.func, ast.Attribute):
            if any(func in node.func.attr.lower() for func in vision_funcs):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "camera" in line_text or "video" in line_text or "real" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML149",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Vision model without physical robustness - real-world attack risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_adversarial_patch_detection_missing(self, node: ast.Call) -> None:
        """AIML150: Detect missing adversarial patch detection."""
        if not self.has_ml_framework:
            return
        
        # Check for object detection without patch detection
        if isinstance(node.func, ast.Attribute):
            if "detect" in node.func.attr.lower():
                violation = RuleViolation(
                    rule_id="AIML150",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Object detection without patch detection - adversarial sticker risk",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Phase 1.4.2: Model Robustness (10 checks - AIML151-AIML160)
    
    def _check_missing_adversarial_training(self, node: ast.Call) -> None:
        """AIML151: Detect missing adversarial training."""
        if not self.has_ml_framework:
            return
        
        # Check for training without adversarial examples
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["fit", "train"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "adversarial" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML151",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model trained without adversarial examples - weak robustness",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-693",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_no_certified_defenses(self, node: ast.Call) -> None:
        """AIML152: Detect lack of certified defenses."""
        if not self.has_ml_framework:
            return
        
        # Check for certified defense mechanisms
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "certify" not in func_name.lower() and "provable" not in str(node).lower():
                if isinstance(node.func, ast.Attribute) and node.func.attr in ["predict", "forward"]:
                    violation = RuleViolation(
                        rule_id="AIML152",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Model lacks certified robustness guarantees",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-693",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_input_gradient_masking(self, node: ast.Call) -> None:
        """AIML153: Detect input gradient masking."""
        if not self.has_ml_framework:
            return
        
        # Check for gradient masking techniques
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "gradient" in line_text and ("mask" in line_text or "obfuscate" in line_text):
            violation = RuleViolation(
                rule_id="AIML153",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="Model uses gradient masking - false sense of security",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML04",
                cwe_id="CWE-693",
                source_tool="pyguard",
            )
            self.violations.append(violation)

    def _check_defensive_distillation_gaps(self, node: ast.Call) -> None:
        """AIML154: Detect defensive distillation gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for defensive distillation usage
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "distillation" in func_name.lower():
                violation = RuleViolation(
                    rule_id="AIML154",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Defensive distillation incomplete - C&W vulnerability",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-693",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_ensemble_defenses_missing(self, node: ast.Call) -> None:
        """AIML155: Detect missing ensemble defenses."""
        if not self.has_ml_framework:
            return
        
        # Check for single model inference (no ensemble)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "ensemble" not in line_text and "voting" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML155",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Single model inference - consider ensemble for robustness",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-693",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_randomization_defense_gaps(self, node: ast.Call) -> None:
        """AIML156: Detect randomization defense gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for randomization-only defense
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "random" in line_text and "defense" in line_text:
            violation = RuleViolation(
                rule_id="AIML156",
                category=RuleCategory.SECURITY,
                severity=RuleSeverity.LOW,
                message="Randomization defense weak - can be circumvented",
                line_number=node.lineno,
                column=node.col_offset,
                end_line_number=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                file_path=str(self.file_path),
                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                fix_applicability=FixApplicability.MANUAL,
                fix_data=None,
                owasp_id="ML04",
                cwe_id="CWE-693",
                source_tool="pyguard",
            )
            self.violations.append(violation)

    def _check_input_transformation_missing(self, node: ast.Call) -> None:
        """AIML157: Detect missing input transformation."""
        if not self.has_ml_framework:
            return
        
        # Check for preprocessing/transformation layers
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "transform" not in line_text and "preprocess" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML157",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="No input preprocessing defenses - add transformation layers",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_detection_mechanism_missing(self, node: ast.Call) -> None:
        """AIML158: Detect missing detection mechanism."""
        if not self.has_ml_framework:
            return
        
        # Check for adversarial detection layer
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "detect" not in line_text or "adversarial" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML158",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="No adversarial example detector - add detection layer",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_rejection_option_missing(self, node: ast.Call) -> None:
        """AIML159: Detect missing rejection option."""
        if not self.has_ml_framework:
            return
        
        # Check for confidence-based rejection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "forward"]:
                has_rejection = any(
                    kw.arg in ["confidence_threshold", "reject_threshold", "min_confidence"]
                    for kw in node.keywords
                )
                
                if not has_rejection:
                    violation = RuleViolation(
                        rule_id="AIML159",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Model lacks confidence-based rejection - add uncertainty quantification",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-754",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_robustness_testing_absent(self, node: ast.Call) -> None:
        """AIML160: Detect absence of robustness testing."""
        if not self.has_ml_framework:
            return
        
        # Check for robustness testing
        test_funcs = ["test", "evaluate", "benchmark"]
        
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if any(test in func_name.lower() for test in test_funcs):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "adversarial" not in line_text and "robust" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML160",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.MEDIUM,
                        message="No adversarial robustness testing - add evaluation suite",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML04",
                        cwe_id="CWE-1059",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    # Phase 2.1: Feature Engineering & Preprocessing (30 checks)
    # Phase 2.1.1: Data Preprocessing Security (15 checks - AIML161-AIML175)
    
    def _check_missing_preprocessing_validation(self, node: ast.Call) -> None:
        """AIML161: Detect missing input validation in preprocessing."""
        if not self.has_ml_framework:
            return
        
        # Check for preprocessing without validation
        preprocessing_funcs = ["fit_transform", "transform", "scale", "normalize", "encode"]
        
        if isinstance(node.func, ast.Attribute):
            if any(func in node.func.attr.lower() for func in preprocessing_funcs):
                # Check if validation is present
                has_validation = any(
                    kw.arg in ["validate", "check_input", "force_all_finite"]
                    for kw in node.keywords
                )
                
                if not has_validation:
                    violation = RuleViolation(
                        rule_id="AIML161",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Preprocessing without input validation - add validation checks",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_normalization_bypass(self, node: ast.Call) -> None:
        """AIML162: Detect normalization bypass attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for normalization without bounds checking
        if isinstance(node.func, ast.Attribute):
            if "normalize" in node.func.attr.lower() or "standard" in node.func.attr.lower():
                # Check for clip/bound parameters
                has_bounds = any(
                    kw.arg in ["clip", "min", "max", "clip_values"]
                    for kw in node.keywords
                )
                
                if not has_bounds:
                    violation = RuleViolation(
                        rule_id="AIML162",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Normalization without bounds checking - bypass attack risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_scaling_manipulation(self, node: ast.Call) -> None:
        """AIML163: Detect feature scaling manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for scaling operations
        if isinstance(node.func, ast.Attribute):
            if "scaler" in node.func.attr.lower() or "scale" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                # Check if scaling parameters are hardcoded
                if "user" in line_text or "input" in line_text or "request" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML163",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature scaling with user input - manipulation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_missing_value_injection(self, node: ast.Call) -> None:
        """AIML164: Detect missing value injection."""
        if not self.has_ml_framework:
            return
        
        # Check for imputation without validation
        if isinstance(node.func, ast.Attribute):
            if "impute" in node.func.attr.lower() or "fillna" in node.func.attr.lower():
                # Check for strategy validation
                has_strategy_validation = any(
                    kw.arg in ["strategy", "method"]
                    for kw in node.keywords
                )
                
                if has_strategy_validation:
                    for kw in node.keywords:
                        if kw.arg in ["strategy", "method"] and not isinstance(kw.value, ast.Constant):
                            violation = RuleViolation(
                                rule_id="AIML164",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.MEDIUM,
                                message="Missing value imputation with dynamic strategy - injection risk",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.SAFE,
                                fix_data=None,
                                owasp_id="ML03",
                                cwe_id="CWE-20",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
    
    def _check_encoding_injection(self, node: ast.Call) -> None:
        """AIML165: Detect encoding injection in categorical features."""
        if not self.has_ml_framework:
            return
        
        # Check for encoding operations
        if isinstance(node.func, ast.Attribute):
            if "encode" in node.func.attr.lower() and "categorical" in str(node).lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "sanitize" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML165",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Categorical encoding without validation - injection risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_extraction_vulnerabilities(self, node: ast.Call) -> None:
        """AIML166: Detect feature extraction vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for feature extraction
        if isinstance(node.func, ast.Attribute):
            if "extract" in node.func.attr.lower() or "feature" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "sanitize" not in line_text and "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML166",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature extraction without validation - vulnerability risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_dimensionality_reduction_poisoning(self, node: ast.Call) -> None:
        """AIML167: Detect dimensionality reduction poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for dimensionality reduction
        if isinstance(node.func, ast.Attribute):
            dim_red_methods = ["pca", "tsne", "umap", "lda", "svd", "nmf"]
            if any(method in node.func.attr.lower() for method in dim_red_methods):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML167",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Dimensionality reduction without validation - poisoning risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_selection_manipulation(self, node: ast.Call) -> None:
        """AIML168: Detect feature selection manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for feature selection
        if isinstance(node.func, ast.Attribute):
            if "selectk" in node.func.attr.lower() or "feature_selection" in str(node).lower():
                # Check if selection criteria is hardcoded
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "user" in line_text or "input" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML168",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature selection with user input - manipulation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_missing_outlier_detection(self, node: ast.Call) -> None:
        """AIML169: Detect missing outlier detection."""
        if not self.has_ml_framework:
            return
        
        # Check for preprocessing without outlier detection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["fit", "fit_transform"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "outlier" not in line_text and "anomaly" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML169",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Preprocessing without outlier detection - consider adding anomaly detection",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_data_leakage_preprocessing(self, node: ast.Call) -> None:
        """AIML170: Detect data leakage in preprocessing."""
        if not self.has_ml_framework:
            return
        
        # Check for fit_transform on entire dataset
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "fit_transform":
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "test" in line_text or "validation" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML170",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Data leakage - fitting preprocessing on test/validation data",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-200",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_test_train_contamination(self, node: ast.Call) -> None:
        """AIML171: Detect test/train contamination."""
        if not self.has_ml_framework:
            return
        
        # Check for train_test_split usage
        if isinstance(node.func, ast.Attribute):
            if "split" in node.func.attr.lower():
                # Check if shuffle is disabled
                has_shuffle = any(
                    kw.arg == "shuffle" and isinstance(kw.value, ast.Constant) and kw.value.value
                    for kw in node.keywords
                )
                
                has_random_state = any(
                    kw.arg == "random_state"
                    for kw in node.keywords
                )
                
                if not has_random_state:
                    violation = RuleViolation(
                        rule_id="AIML171",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.MEDIUM,
                        message="Train/test split without random_state - reproducibility risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-330",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_store_injection(self, node: ast.Call) -> None:
        """AIML172: Detect feature store injection."""
        if not self.has_ml_framework:
            return
        
        # Check for feature store operations
        if isinstance(node.func, ast.Attribute):
            if "feature" in node.func.attr.lower() and "get" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "sanitize" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML172",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature store access without validation - injection risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_pipeline_versioning_gaps(self, node: ast.Call) -> None:
        """AIML173: Detect pipeline versioning gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for pipeline save/load without version
        if isinstance(node.func, ast.Attribute):
            if "pipeline" in str(node).lower() and node.func.attr in ["save", "dump", "pickle"]:
                # Check if version is specified
                has_version = any(
                    kw.arg in ["version", "metadata"]
                    for kw in node.keywords
                )
                
                if not has_version:
                    violation = RuleViolation(
                        rule_id="AIML173",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Pipeline saved without version metadata - tracking risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-778",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_preprocessing_state_tampering(self, node: ast.Call) -> None:
        """AIML174: Detect preprocessing state tampering."""
        if not self.has_ml_framework:
            return
        
        # Check for preprocessor state loading
        if isinstance(node.func, ast.Attribute):
            if "load" in node.func.attr.lower() and ("scaler" in str(node).lower() or "encoder" in str(node).lower()):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "verify" not in line_text and "checksum" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML174",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Preprocessing state loaded without integrity check - tampering risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-494",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_transformation_order_vulnerabilities(self, node: ast.Call) -> None:
        """AIML175: Detect transformation order vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for make_pipeline usage
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            func_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            
            if "pipeline" in func_name.lower():
                # Pipeline order matters for security
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "comment" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML175",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Pipeline transformation order - document to prevent vulnerabilities",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-693",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    # Phase 2.1.2: Feature Store Security (15 checks - AIML176-AIML190)
    
    def _check_feast_feature_store_injection(self, node: ast.Call) -> None:
        """AIML176: Detect Feast feature store injection."""
        if not self.has_ml_framework:
            return
        
        # Check for Feast feature store operations
        if isinstance(node.func, ast.Attribute):
            if "feast" in str(node).lower() or "feature_store" in node.func.attr.lower():
                # Check for SQL/NoSQL injection in feature queries
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if any(keyword in line_text for keyword in ["user", "input", "request", "param"]):
                    violation = RuleViolation(
                        rule_id="AIML176",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Feast feature store query with user input - injection risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-89",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_missing_feature_validation(self, node: ast.Call) -> None:
        """AIML177: Detect missing feature validation."""
        if not self.has_ml_framework:
            return
        
        # Check for feature retrieval without validation
        if isinstance(node.func, ast.Attribute):
            if "get_features" in node.func.attr.lower() or "fetch_features" in node.func.attr.lower():
                # Check if validation is present
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "check" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML177",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature retrieval without validation - integrity risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_drift_without_detection(self, node: ast.Call) -> None:
        """AIML178: Detect feature drift without detection."""
        if not self.has_ml_framework:
            return
        
        # Check for feature serving without drift monitoring
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "transform", "get_features"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "drift" not in line_text and "monitor" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML178",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Feature usage without drift detection - add monitoring",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML06",
                        cwe_id="CWE-754",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_serving_vulnerabilities(self, node: ast.Call) -> None:
        """AIML179: Detect feature serving vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for feature serving endpoints
        if isinstance(node.func, ast.Attribute):
            if "serve" in node.func.attr.lower() and "feature" in str(node).lower():
                # Check for authentication
                has_auth = any(
                    kw.arg in ["auth", "authentication", "token", "api_key"]
                    for kw in node.keywords
                )
                
                if not has_auth:
                    violation = RuleViolation(
                        rule_id="AIML179",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Feature serving without authentication - access control risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="A01",
                        cwe_id="CWE-306",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_offline_online_feature_skew(self, node: ast.Call) -> None:
        """AIML180: Detect offline/online feature skew."""
        if not self.has_ml_framework:
            return
        
        # Check for online feature serving
        if isinstance(node.func, ast.Attribute):
            if "online" in node.func.attr.lower() or "real_time" in str(node).lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "consistency" not in line_text and "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML180",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.MEDIUM,
                        message="Online feature serving - validate consistency with offline features",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-754",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_metadata_tampering(self, node: ast.Call) -> None:
        """AIML181: Detect feature metadata tampering."""
        if not self.has_ml_framework:
            return
        
        # Check for metadata updates
        if isinstance(node.func, ast.Attribute):
            if "metadata" in node.func.attr.lower() and "update" in node.func.attr.lower():
                # Check for integrity verification
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "verify" not in line_text and "checksum" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML181",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature metadata update without integrity check - tampering risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-494",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_lineage_missing(self, node: ast.Call) -> None:
        """AIML182: Detect missing feature lineage."""
        if not self.has_ml_framework:
            return
        
        # Check for feature creation without lineage tracking
        if isinstance(node.func, ast.Attribute):
            if "create_feature" in node.func.attr.lower() or "register_feature" in node.func.attr.lower():
                # Check for lineage metadata
                has_lineage = any(
                    kw.arg in ["lineage", "source", "provenance", "metadata"]
                    for kw in node.keywords
                )
                
                if not has_lineage:
                    violation = RuleViolation(
                        rule_id="AIML182",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Feature creation without lineage tracking - add provenance metadata",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-778",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_access_control_gaps(self, node: ast.Call) -> None:
        """AIML183: Detect feature access control gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for feature access without authorization
        if isinstance(node.func, ast.Attribute):
            if "get_features" in node.func.attr.lower() or "access" in node.func.attr.lower():
                # Check for authorization
                has_auth = any(
                    kw.arg in ["user", "role", "permissions", "acl"]
                    for kw in node.keywords
                )
                
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if not has_auth and "auth" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML183",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Feature access without authorization - add access control",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="A01",
                        cwe_id="CWE-862",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_deletion_corruption(self, node: ast.Call) -> None:
        """AIML184: Detect feature deletion/corruption risks."""
        if not self.has_ml_framework:
            return
        
        # Check for feature deletion operations
        if isinstance(node.func, ast.Attribute):
            if "delete" in node.func.attr.lower() and "feature" in str(node).lower():
                # Check for soft delete or backup
                has_backup = any(
                    kw.arg in ["backup", "archive", "soft_delete"]
                    for kw in node.keywords
                )
                
                if not has_backup:
                    violation = RuleViolation(
                        rule_id="AIML184",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature deletion without backup - data loss risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-404",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_version_control_weaknesses(self, node: ast.Call) -> None:
        """AIML185: Detect feature version control weaknesses."""
        if not self.has_ml_framework:
            return
        
        # Check for feature updates without versioning
        if isinstance(node.func, ast.Attribute):
            if "update_feature" in node.func.attr.lower() or "modify_feature" in node.func.attr.lower():
                # Check for version parameter
                has_version = any(
                    kw.arg in ["version", "revision"]
                    for kw in node.keywords
                )
                
                if not has_version:
                    violation = RuleViolation(
                        rule_id="AIML185",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.LOW,
                        message="Feature update without version control - tracking risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-778",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_freshness_attacks(self, node: ast.Call) -> None:
        """AIML186: Detect feature freshness attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for feature serving without freshness validation
        if isinstance(node.func, ast.Attribute):
            if "get_features" in node.func.attr.lower() or "serve" in node.func.attr.lower():
                # Check for timestamp/ttl validation
                has_freshness = any(
                    kw.arg in ["ttl", "max_age", "timestamp", "freshness"]
                    for kw in node.keywords
                )
                
                if not has_freshness:
                    violation = RuleViolation(
                        rule_id="AIML186",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature serving without freshness validation - stale data risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-672",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_batch_realtime_inconsistencies(self, node: ast.Call) -> None:
        """AIML187: Detect batch vs real-time inconsistencies."""
        if not self.has_ml_framework:
            return
        
        # Check for batch processing
        if isinstance(node.func, ast.Attribute):
            if "batch" in node.func.attr.lower() and "feature" in str(node).lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "consistency" not in line_text and "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML187",
                        category=RuleCategory.CONVENTION,
                        severity=RuleSeverity.MEDIUM,
                        message="Batch feature processing - validate consistency with real-time",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-754",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_engineering_code_injection(self, node: ast.Call) -> None:
        """AIML188: Detect feature engineering code injection."""
        if not self.has_ml_framework:
            return
        
        # Check for dynamic feature engineering
        if isinstance(node.func, ast.Attribute):
            if "feature" in node.func.attr.lower() and "transform" in node.func.attr.lower():
                # Check if transformation uses user input
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if any(keyword in line_text for keyword in ["user", "input", "request", "eval", "exec"]):
                    violation = RuleViolation(
                        rule_id="AIML188",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Feature transformation with dynamic code - injection risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="A03",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_schema_evolution_attacks(self, node: ast.Call) -> None:
        """AIML189: Detect schema evolution attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for schema updates
        if isinstance(node.func, ast.Attribute):
            if "schema" in node.func.attr.lower() and ("update" in node.func.attr.lower() or "evolve" in node.func.attr.lower()):
                # Check for validation
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "verify" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML189",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Schema evolution without validation - compatibility risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_importance_manipulation(self, node: ast.Call) -> None:
        """AIML190: Detect feature importance manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for feature importance calculations
        if isinstance(node.func, ast.Attribute):
            if "feature_importances" in node.func.attr.lower() or "permutation_importance" in str(node).lower():
                # Check if importance is user-controllable
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "user" in line_text or "input" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML190",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Feature importance calculation with user input - manipulation risk",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    # Phase 2.2: Model Training Infrastructure (35 checks)
    # Phase 2.2.1: Distributed Training Security (15 checks - AIML191-AIML205)
    
    def _check_parameter_server_vulnerabilities(self, node: ast.Call) -> None:
        """AIML191: Detect parameter server vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for parameter server usage without security
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "parameterserver" in line_text.replace(" ", "") or "parameter_server" in line_text:
            if "ssl" not in line_text and "tls" not in line_text and "encrypt" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML191",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Parameter server - implement authentication and encryption",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_gradient_aggregation_poisoning(self, node: ast.Call) -> None:
        """AIML192: Detect gradient aggregation poisoning."""
        if not self.has_pytorch:
            return
        
        # Check for gradient aggregation
        if isinstance(node.func, ast.Attribute):
            if "aggregate" in node.func.attr.lower() or "all_reduce" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "gradient" in line_text or "grad" in line_text:
                    if "validate" not in line_text and "verify" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML192",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="Gradient aggregation - validate to prevent poisoning attacks",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-345",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_byzantine_worker_attacks(self, node: ast.Call) -> None:
        """AIML193: Detect Byzantine worker attack vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for distributed training without Byzantine detection
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "distributed" in line_text and ("worker" in line_text or "node" in line_text):
            if "byzantine" not in line_text and "krum" not in line_text and "median" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML193",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Distributed training - add Byzantine worker detection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_all_reduce_manipulation(self, node: ast.Call) -> None:
        """AIML194: Detect All-Reduce manipulation risks."""
        if not self.has_pytorch:
            return
        
        # Check for all_reduce operations
        if isinstance(node.func, ast.Attribute):
            if "all_reduce" in node.func.attr.lower():
                # Check for validation
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "verify" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML194",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="All-Reduce operation - validate tensor values to prevent manipulation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_ring_all_reduce_injection(self, node: ast.Call) -> None:
        """AIML195: Detect Ring-All-Reduce injection risks."""
        if not self.has_ml_framework:
            return
        
        # Check for ring all-reduce patterns
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "ring" in line_text and "allreduce" in line_text.replace("-", "").replace("_", ""):
            if "secure" not in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML195",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Ring-All-Reduce - implement secure communication to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_horovod_security_gaps(self, node: ast.Call) -> None:
        """AIML196: Detect Horovod security gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for Horovod usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "horovod" in line_text or "hvd" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "init" in node.func.attr or "broadcast" in node.func.attr:
                    # Check for TLS/encryption
                    if "tls" not in line_text and "ssl" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML196",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Horovod communication - enable TLS for secure distributed training",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-300",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_deepspeed_vulnerabilities(self, node: ast.Call) -> None:
        """AIML197: Detect DeepSpeed vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for DeepSpeed usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "deepspeed" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "initialize" in node.func.attr or "init" in node.func.attr:
                    # Check for secure configuration
                    if "config" not in line_text or ("validate" not in line_text and "verify" not in line_text):
                        violation = RuleViolation(
                            rule_id="AIML197",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="DeepSpeed initialization - validate configuration to prevent vulnerabilities",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-20",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_fsdp_risks(self, node: ast.Call) -> None:
        """AIML198: Detect FSDP (Fully Sharded Data Parallel) risks."""
        if not self.has_pytorch:
            return
        
        # Check for FSDP usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "fsdp" in line_text or "fullyshareddataparallel" in line_text.replace("_", ""):
            if "secure" not in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML198",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="FSDP training - implement shard validation to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_zero_optimizer_state_attacks(self, node: ast.Call) -> None:
        """AIML199: Detect ZeRO optimizer state attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for ZeRO optimizer usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "zero" in line_text and ("optimizer" in line_text or "stage" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML199",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ZeRO optimizer state - validate state integrity to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_parallel_partition_poisoning(self, node: ast.Call) -> None:
        """AIML200: Detect model parallel partition poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for model parallelism
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "model" in line_text and "parallel" in line_text and ("partition" in line_text or "shard" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML200",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model parallel partitioning - validate partition integrity",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_pipeline_parallel_injection(self, node: ast.Call) -> None:
        """AIML201: Detect pipeline parallel injection risks."""
        if not self.has_ml_framework:
            return
        
        # Check for pipeline parallelism
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "pipeline" in line_text and "parallel" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML201",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Pipeline parallel training - validate stage outputs to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tensor_parallel_tampering(self, node: ast.Call) -> None:
        """AIML202: Detect tensor parallel tampering."""
        if not self.has_ml_framework:
            return
        
        # Check for tensor parallelism
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "tensor" in line_text and "parallel" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML202",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Tensor parallel training - validate tensor splits to prevent tampering",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_mixed_precision_training_risks(self, node: ast.Call) -> None:
        """AIML203: Detect mixed precision training risks."""
        if not self.has_ml_framework:
            return
        
        # Check for mixed precision training
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("amp" in line_text or "autocast" in line_text or "mixed" in line_text) and "precision" in line_text:
            if "validate" not in line_text and "check" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML203",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Mixed precision training - validate numerical stability to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_communication_backend_vulnerabilities(self, node: ast.Call) -> None:
        """AIML204: Detect communication backend vulnerabilities."""
        if not self.has_pytorch:
            return
        
        # Check for distributed backend initialization
        if isinstance(node.func, ast.Attribute):
            if "init_process_group" in node.func.attr:
                # Check for backend security
                has_secure_backend = False
                for keyword in node.keywords:
                    if keyword.arg == "backend":
                        if isinstance(keyword.value, ast.Constant):
                            backend = keyword.value.value
                            if "nccl" in str(backend).lower():
                                has_secure_backend = True
                
                if not has_secure_backend:
                    violation = RuleViolation(
                        rule_id="AIML204",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Communication backend - use secure backend (e.g., NCCL) for distributed training",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-300",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_collective_operation_manipulation(self, node: ast.Call) -> None:
        """AIML205: Detect collective operation manipulation."""
        if not self.has_pytorch:
            return
        
        # Check for collective operations
        if isinstance(node.func, ast.Attribute):
            collective_ops = ["all_gather", "broadcast", "reduce", "scatter", "barrier"]
            if any(op in node.func.attr.lower() for op in collective_ops):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "verify" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML205",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Collective operation - validate tensor data to prevent manipulation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    # Phase 2.2.2: GPU & Accelerator Security (10 checks - AIML206-AIML215)
    
    def _check_gpu_memory_leakage_aiml206(self, node: ast.Call) -> None:
        """AIML206: Detect GPU memory leakage."""
        if not self.has_pytorch:
            return
        
        # Check for GPU memory allocation without cleanup
        if isinstance(node.func, ast.Attribute):
            if "cuda" in str(node).lower() or "to" in node.func.attr:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "device" in line_text or "cuda" in line_text:
                    # Look for memory management
                    context_lines = []
                    start = max(0, node.lineno - 5)
                    end = min(len(self.lines), node.lineno + 5)
                    context_lines = [self.lines[i].lower() for i in range(start, end)]
                    context_text = " ".join(context_lines)
                    
                    if "empty_cache" not in context_text and "del" not in context_text:
                        violation = RuleViolation(
                            rule_id="AIML206",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="GPU memory allocation - ensure proper cleanup to prevent memory leaks",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-401",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_cuda_kernel_injection(self, node: ast.Call) -> None:
        """AIML207: Detect CUDA kernel injection risks."""
        if not self.has_pytorch:
            return
        
        # Check for custom CUDA kernel usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "cuda" in line_text and ("kernel" in line_text or "jit" in line_text or "load" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML207",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Custom CUDA kernel - validate source to prevent code injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_rocm_vulnerabilities(self, node: ast.Call) -> None:
        """AIML208: Detect ROCm vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for ROCm usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "rocm" in line_text or "hip" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML208",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ROCm usage - validate kernel code and memory management",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tpu_security_gaps(self, node: ast.Call) -> None:
        """AIML209: Detect TPU security gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for TPU usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "tpu" in line_text or "xla" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML209",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="TPU usage - validate computation and memory management",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_npu_ipu_risks(self, node: ast.Call) -> None:
        """AIML210: Detect NPU/IPU risks."""
        if not self.has_ml_framework:
            return
        
        # Check for NPU/IPU usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "npu" in line_text or "ipu" in line_text or "graphcore" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML210",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="NPU/IPU usage - validate accelerator configuration and operations",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_multi_gpu_synchronization_attacks(self, node: ast.Call) -> None:
        """AIML211: Detect multi-GPU synchronization attack risks."""
        if not self.has_pytorch:
            return
        
        # Check for multi-GPU operations
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("datagparallel" in line_text.replace("_", "") or "distributeddataparallel" in line_text.replace("_", "")):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML211",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Multi-GPU training - validate synchronization to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_device_placement_manipulation(self, node: ast.Call) -> None:
        """AIML212: Detect device placement manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for device placement
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "to" or "device" in node.func.attr.lower():
                # Check if device is user-controllable
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                        if "user" in line_text or "input" in line_text:
                            violation = RuleViolation(
                                rule_id="AIML212",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.MEDIUM,
                                message="Device placement with user input - manipulation risk",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.SAFE,
                                fix_data=None,
                                owasp_id="ML03",
                                cwe_id="CWE-345",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                            break
    
    def _check_cuda_graph_poisoning(self, node: ast.Call) -> None:
        """AIML213: Detect CUDA graph poisoning."""
        if not self.has_pytorch:
            return
        
        # Check for CUDA graph usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "cuda" in line_text and "graph" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML213",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="CUDA graph - validate graph structure to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_kernel_launch_parameter_tampering(self, node: ast.Call) -> None:
        """AIML214: Detect kernel launch parameter tampering."""
        if not self.has_pytorch:
            return
        
        # Check for kernel launches
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "kernel" in line_text and ("launch" in line_text or "call" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML214",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Kernel launch - validate parameters to prevent tampering",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_gpu_memory_exhaustion_attacks(self, node: ast.Call) -> None:
        """AIML215: Detect GPU memory exhaustion attack risks."""
        if not self.has_pytorch:
            return
        
        # Check for large tensor allocations
        if isinstance(node.func, ast.Attribute):
            if "tensor" in node.func.attr.lower() or "empty" in node.func.attr or "zeros" in node.func.attr or "ones" in node.func.attr:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "cuda" in line_text or "device" in line_text:
                    # Check for size validation
                    if "validate" not in line_text and "check" not in line_text and "limit" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML215",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="GPU tensor allocation - validate size to prevent memory exhaustion",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-400",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    # Phase 2.2.3: Experiment Tracking Security (10 checks - AIML216-AIML225)
    
    def _check_mlflow_injection_attacks(self, node: ast.Call) -> None:
        """AIML216: Detect MLflow injection attacks."""
        if not self.has_ml_framework:
            return
        
        # Check for MLflow usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "mlflow" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "log" in node.func.attr or "set" in node.func.attr:
                    # Check for user input
                    if "user" in line_text or "input" in line_text:
                        violation = RuleViolation(
                            rule_id="AIML216",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="MLflow logging with user input - injection risk, validate data",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_wandb_credential_leakage(self, node: ast.Call) -> None:
        """AIML217: Detect Weights & Biases credential leakage."""
        if not self.has_ml_framework:
            return
        
        # Check for wandb usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "wandb" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "init" in node.func.attr or "login" in node.func.attr:
                    # Check for hardcoded keys
                    for keyword in node.keywords:
                        if keyword.arg in ["api_key", "key"]:
                            if isinstance(keyword.value, ast.Constant):
                                violation = RuleViolation(
                                    rule_id="AIML217",
                                    category=RuleCategory.SECURITY,
                                    severity=RuleSeverity.CRITICAL,
                                    message="Weights & Biases API key hardcoded - use environment variables",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    end_line_number=getattr(node, "end_lineno", node.lineno),
                                    end_column=getattr(node, "end_col_offset", node.col_offset),
                                    file_path=str(self.file_path),
                                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                    fix_applicability=FixApplicability.SAFE,
                                    fix_data=None,
                                    owasp_id="A07",
                                    cwe_id="CWE-798",
                                    source_tool="pyguard",
                                )
                                self.violations.append(violation)
    
    def _check_cometml_experiment_tampering(self, node: ast.Call) -> None:
        """AIML218: Detect Comet.ml experiment tampering."""
        if not self.has_ml_framework:
            return
        
        # Check for comet_ml usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "comet" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "log" in node.func.attr or "set" in node.func.attr:
                    # Check for validation
                    if "validate" not in line_text and "verify" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML218",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Comet.ml experiment data - validate to prevent tampering",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-345",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_tensorboard_rce(self, node: ast.Call) -> None:
        """AIML219: Detect TensorBoard remote code execution risks."""
        if not self.has_tensorflow:
            return
        
        # Check for TensorBoard usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "tensorboard" in line_text or "summarywriter" in line_text.replace("_", ""):
            if isinstance(node.func, ast.Attribute):
                if "add" in node.func.attr or "log" in node.func.attr:
                    # Check for user input
                    if "user" in line_text or "input" in line_text:
                        violation = RuleViolation(
                            rule_id="AIML219",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.CRITICAL,
                            message="TensorBoard logging with user input - RCE risk, sanitize data",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-94",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_neptuneai_model_manipulation(self, node: ast.Call) -> None:
        """AIML220: Detect Neptune.ai model manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for Neptune.ai usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "neptune" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "log" in node.func.attr or "upload" in node.func.attr:
                    # Check for validation
                    if "validate" not in line_text and "verify" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML220",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="Neptune.ai model logging - validate data to prevent manipulation",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.MANUAL,
                            fix_data=None,
                            owasp_id="ML03",
                            cwe_id="CWE-345",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_experiment_metadata_injection(self, node: ast.Call) -> None:
        """AIML221: Detect experiment metadata injection."""
        if not self.has_ml_framework:
            return
        
        # Check for metadata logging
        if isinstance(node.func, ast.Attribute):
            if "metadata" in node.func.attr.lower() or "tag" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "user" in line_text or "input" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML221",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Experiment metadata with user input - injection risk, sanitize data",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-94",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_metric_tampering(self, node: ast.Call) -> None:
        """AIML222: Detect metric tampering."""
        if not self.has_ml_framework:
            return
        
        # Check for metric logging
        if isinstance(node.func, ast.Attribute):
            if "log_metric" in node.func.attr.lower() or "log_metrics" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "verify" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML222",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Metric logging - validate values to prevent tampering",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_artifact_poisoning(self, node: ast.Call) -> None:
        """AIML223: Detect artifact poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for artifact logging
        if isinstance(node.func, ast.Attribute):
            if "log_artifact" in node.func.attr.lower() or "upload" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "validate" not in line_text and "verify" not in line_text and "checksum" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML223",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Artifact upload - validate integrity with checksums to prevent poisoning",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML05",
                        cwe_id="CWE-494",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_run_comparison_manipulation(self, node: ast.Call) -> None:
        """AIML224: Detect run comparison manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for run comparison
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "compare" in line_text and ("run" in line_text or "experiment" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML224",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Run comparison - validate run IDs to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_hyperparameter_logging_risks(self, node: ast.Call) -> None:
        """AIML225: Detect hyperparameter logging risks."""
        if not self.has_ml_framework:
            return
        
        # Check for hyperparameter logging
        if isinstance(node.func, ast.Attribute):
            if "log_param" in node.func.attr.lower() or "log_hyperparameter" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                # Check for sensitive data in parameters
                if "key" in line_text or "password" in line_text or "secret" in line_text or "token" in line_text:
                    violation = RuleViolation(
                        rule_id="AIML225",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Hyperparameter logging - avoid logging sensitive data (keys, passwords)",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="A02",
                        cwe_id="CWE-200",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    # Phase 2.3: Model Deployment & Serving (35 checks)
    # Phase 2.3.1: Model Serving Vulnerabilities (15 checks - AIML226-AIML240)
    
    def _check_torchserve_vulnerabilities(self, node: ast.Call) -> None:
        """AIML226: Detect TorchServe vulnerabilities."""
        if not self.has_pytorch:
            return
        
        # Check for TorchServe usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "torchserve" in line_text or "torch-model-archiver" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML226",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="TorchServe deployment - validate model and handler code",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_tensorflow_serving_injection(self, node: ast.Call) -> None:
        """AIML227: Detect TensorFlow Serving injection risks."""
        if not self.has_tensorflow:
            return
        
        # Check for TensorFlow Serving
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "tensorflow_serving" in line_text.replace("-", "_") or "tf_serving" in line_text:
            if "validate" not in line_text and "sanitize" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML227",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="TensorFlow Serving - validate input data to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_onnx_runtime_risks(self, node: ast.Call) -> None:
        """AIML228: Detect ONNX Runtime risks."""
        if not self.has_ml_framework:
            return
        
        # Check for ONNX Runtime usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "onnxruntime" in line_text.replace("_", "").replace("-", "") or "ort" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "inferenc" in node.func.attr.lower() or "run" in node.func.attr:
                    if "validate" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML228",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="ONNX Runtime inference - validate input shapes and types",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML05",
                            cwe_id="CWE-20",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_triton_inference_server_gaps(self, node: ast.Call) -> None:
        """AIML229: Detect Triton Inference Server security gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for Triton usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "triton" in line_text and ("inference" in line_text or "server" in line_text):
            if "auth" not in line_text and "secure" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML229",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Triton Inference Server - implement authentication and encryption",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="A07",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bentoml_security_issues(self, node: ast.Call) -> None:
        """AIML230: Detect BentoML security issues."""
        if not self.has_ml_framework:
            return
        
        # Check for BentoML usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "bentoml" in line_text or "bento" in line_text:
            if isinstance(node.func, ast.Attribute):
                if "serve" in node.func.attr.lower() or "api" in node.func.attr.lower():
                    if "auth" not in line_text and "validate" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML230",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="BentoML service - add authentication and input validation",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="A07",
                            cwe_id="CWE-306",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_ray_serve_vulnerabilities(self, node: ast.Call) -> None:
        """AIML231: Detect Ray Serve vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for Ray Serve usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "ray" in line_text and "serve" in line_text:
            if "auth" not in line_text and "secure" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML231",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Ray Serve deployment - implement authentication and security",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="A07",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_seldon_core_risks(self, node: ast.Call) -> None:
        """AIML232: Detect Seldon Core risks."""
        if not self.has_ml_framework:
            return
        
        # Check for Seldon Core usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "seldon" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML232",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Seldon Core deployment - validate model and input data",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_kserve_weaknesses(self, node: ast.Call) -> None:
        """AIML233: Detect KServe weaknesses."""
        if not self.has_ml_framework:
            return
        
        # Check for KServe usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "kserve" in line_text or "kfserving" in line_text:
            if "auth" not in line_text and "secure" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML233",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="KServe deployment - implement authentication and security policies",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="A07",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_batching_attacks(self, node: ast.Call) -> None:
        """AIML234: Detect model batching attack risks."""
        if not self.has_ml_framework:
            return
        
        # Check for batching operations
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "batch" in line_text and ("inference" in line_text or "predict" in line_text):
            if "validate" not in line_text and "limit" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML234",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model batching - validate batch size to prevent resource exhaustion",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_dynamic_batching_poisoning(self, node: ast.Call) -> None:
        """AIML235: Detect dynamic batching poisoning."""
        if not self.has_ml_framework:
            return
        
        # Check for dynamic batching
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "dynamic" in line_text and "batch" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML235",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Dynamic batching - validate batch composition to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_versioning_bypass(self, node: ast.Call) -> None:
        """AIML236: Detect model versioning bypass risks."""
        if not self.has_ml_framework:
            return
        
        # Check for model loading without version
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("load" in line_text or "get" in line_text) and "model" in line_text:
            if "version" not in line_text and "tag" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML236",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Model loading - specify version to prevent unintended model usage",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-494",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_ab_testing_manipulation(self, node: ast.Call) -> None:
        """AIML237: Detect A/B testing manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for A/B testing
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("a/b" in line_text or "ab_test" in line_text or "abtest" in line_text):
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML237",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="A/B testing - validate assignment logic to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_canary_deployment_risks(self, node: ast.Call) -> None:
        """AIML238: Detect canary deployment risks."""
        if not self.has_ml_framework:
            return
        
        # Check for canary deployments
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "canary" in line_text:
            if "validate" not in line_text and "monitor" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML238",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Canary deployment - implement monitoring and validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_blue_green_deployment_gaps(self, node: ast.Call) -> None:
        """AIML239: Detect blue-green deployment gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for blue-green deployments
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("blue" in line_text and "green" in line_text) or "bluegreen" in line_text:
            if "validate" not in line_text and "rollback" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML239",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Blue-green deployment - ensure rollback capability and validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_shadow_deployment_leakage(self, node: ast.Call) -> None:
        """AIML240: Detect shadow deployment information leakage."""
        if not self.has_ml_framework:
            return
        
        # Check for shadow deployments
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "shadow" in line_text and ("deploy" in line_text or "model" in line_text):
            if "log" in line_text and "sanitize" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML240",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Shadow deployment - sanitize logs to prevent information leakage",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="A02",
                    cwe_id="CWE-200",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    # Phase 2.3.2: API & Endpoint Security (12 checks - AIML241-AIML252)
    
    def _check_missing_authentication_inference_api(self, node: ast.Call) -> None:
        """AIML241: Detect missing authentication on inference API."""
        if not self.has_ml_framework:
            return
        
        # Check for API route definitions
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("route" in line_text or "endpoint" in line_text or "api" in line_text) and ("predict" in line_text or "inference" in line_text):
            if "auth" not in line_text and "token" not in line_text and "key" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML241",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Inference API - add authentication to prevent unauthorized access",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="A07",
                    cwe_id="CWE-306",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_endpoint_enumeration(self, node: ast.Call) -> None:
        """AIML242: Detect model endpoint enumeration risks."""
        if not self.has_ml_framework:
            return
        
        # Check for model listing endpoints
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("list" in line_text or "get_all" in line_text) and ("model" in line_text or "endpoint" in line_text):
            if "auth" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML242",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model endpoint enumeration - restrict access to model listing",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="A01",
                    cwe_id="CWE-200",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_batch_inference_injection(self, node: ast.Call) -> None:
        """AIML243: Detect batch inference injection risks."""
        if not self.has_ml_framework:
            return
        
        # Check for batch inference
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "batch" in line_text and ("predict" in line_text or "inference" in line_text):
            if "validate" not in line_text and "sanitize" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML243",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Batch inference - validate each input to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_streaming_inference_attacks(self, node: ast.Call) -> None:
        """AIML244: Detect streaming inference attack risks."""
        if not self.has_ml_framework:
            return
        
        # Check for streaming inference
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "stream" in line_text and ("predict" in line_text or "inference" in line_text):
            if "validate" not in line_text and "rate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML244",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Streaming inference - implement rate limiting and validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_cache_poisoning(self, node: ast.Call) -> None:
        """AIML245: Detect model cache poisoning risks."""
        if not self.has_ml_framework:
            return
        
        # Check for model caching
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "cache" in line_text and "model" in line_text:
            if "validate" not in line_text and "ttl" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML245",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model cache - implement validation and TTL to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_prediction_logging_risks(self, node: ast.Call) -> None:
        """AIML246: Detect prediction logging PII risks."""
        if not self.has_ml_framework:
            return
        
        # Check for prediction logging
        if isinstance(node.func, ast.Attribute):
            if "log" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "predict" in line_text or "inference" in line_text or "output" in line_text:
                    if "sanitize" not in line_text and "redact" not in line_text:
                        violation = RuleViolation(
                            rule_id="AIML246",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="Prediction logging - sanitize to prevent PII leakage",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="A02",
                            cwe_id="CWE-532",
                            source_tool="pyguard",
                        )
                        self.violations.append(violation)
    
    def _check_model_warmup_vulnerabilities(self, node: ast.Call) -> None:
        """AIML247: Detect model warm-up vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for model warm-up
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "warmup" in line_text.replace("-", "").replace("_", "") or "warm_up" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML247",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Model warm-up - validate warm-up data to prevent exploitation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_health_check_information_disclosure(self, node: ast.Call) -> None:
        """AIML248: Detect health check information disclosure."""
        if not self.has_ml_framework:
            return
        
        # Check for health check endpoints
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "health" in line_text or "readiness" in line_text or "liveness" in line_text:
            if "version" in line_text or "model" in line_text:
                violation = RuleViolation(
                    rule_id="AIML248",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Health check - avoid exposing sensitive model information",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="A01",
                    cwe_id="CWE-200",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_metrics_endpoint_exposure(self, node: ast.Call) -> None:
        """AIML249: Detect metrics endpoint exposure."""
        if not self.has_ml_framework:
            return
        
        # Check for metrics endpoints
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "metrics" in line_text and ("endpoint" in line_text or "route" in line_text):
            if "auth" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML249",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Metrics endpoint - restrict access with authentication",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="A01",
                    cwe_id="CWE-200",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_metadata_leakage(self, node: ast.Call) -> None:
        """AIML250: Detect model metadata leakage."""
        if not self.has_ml_framework:
            return
        
        # Check for model metadata exposure
        if isinstance(node.func, ast.Attribute):
            if "metadata" in node.func.attr.lower() or "info" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                
                if "model" in line_text and ("return" in line_text or "response" in line_text):
                    violation = RuleViolation(
                        rule_id="AIML250",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Model metadata - avoid exposing sensitive model information",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="A01",
                        cwe_id="CWE-200",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_feature_flag_manipulation(self, node: ast.Call) -> None:
        """AIML251: Detect feature flag manipulation."""
        if not self.has_ml_framework:
            return
        
        # Check for feature flags
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "feature" in line_text and ("flag" in line_text or "toggle" in line_text):
            if "user" in line_text or "input" in line_text:
                violation = RuleViolation(
                    rule_id="AIML251",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Feature flag - prevent user manipulation of model behavior flags",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_circuit_breaker_bypass(self, node: ast.Call) -> None:
        """AIML252: Detect circuit breaker bypass risks."""
        if not self.has_ml_framework:
            return
        
        # Check for circuit breaker usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "circuit" in line_text and "breaker" in line_text:
            if "validate" not in line_text and "enforce" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML252",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Circuit breaker - ensure proper enforcement to prevent bypass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    # Phase 2.3.3: Edge & Mobile Deployment (8 checks - AIML253-AIML260)
    
    def _check_tflite_model_tampering(self, node: ast.Call) -> None:
        """AIML253: Detect TFLite model tampering."""
        if not self.has_tensorflow:
            return
        
        # Check for TFLite usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "tflite" in line_text:
            if "validate" not in line_text and "verify" not in line_text and "checksum" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML253",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="TFLite model - verify integrity with checksums to prevent tampering",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-494",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_coreml_injection(self, node: ast.Call) -> None:
        """AIML254: Detect Core ML injection risks."""
        if not self.has_ml_framework:
            return
        
        # Check for Core ML usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "coreml" in line_text:
            if "validate" not in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML254",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Core ML model - validate model source and integrity",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-94",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_onnx_mobile_risks(self, node: ast.Call) -> None:
        """AIML255: Detect ONNX mobile deployment risks."""
        if not self.has_ml_framework:
            return
        
        # Check for ONNX mobile usage
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "onnx" in line_text and ("mobile" in line_text or "edge" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML255",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ONNX mobile - validate model integrity and input data",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_quantized_model_vulnerabilities(self, node: ast.Call) -> None:
        """AIML256: Detect quantized model vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for model quantization
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "quantiz" in line_text:
            if "validate" not in line_text and "test" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML256",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Quantized model - validate accuracy and behavior to prevent degradation attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_model_pruning_attacks(self, node: ast.Call) -> None:
        """AIML257: Detect model pruning attack risks."""
        if not self.has_ml_framework:
            return
        
        # Check for model pruning
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "prun" in line_text:
            if "validate" not in line_text and "test" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML257",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Model pruning - validate pruned model to prevent backdoor retention",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_knowledge_distillation_risks(self, node: ast.Call) -> None:
        """AIML258: Detect knowledge distillation risks."""
        if not self.has_ml_framework:
            return
        
        # Check for knowledge distillation
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "distill" in line_text:
            if "validate" not in line_text and "teacher" in line_text:
                violation = RuleViolation(
                    rule_id="AIML258",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Knowledge distillation - validate teacher model to prevent poisoning transfer",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML05",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_on_device_training_weaknesses(self, node: ast.Call) -> None:
        """AIML259: Detect on-device training weaknesses."""
        if not self.has_ml_framework:
            return
        
        # Check for on-device training
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("on" in line_text and "device" in line_text and "train" in line_text) or "ondevice" in line_text:
            if "validate" not in line_text and "secure" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML259",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="On-device training - validate training data and model updates",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_federated_learning_gaps(self, node: ast.Call) -> None:
        """AIML260: Detect federated learning security gaps."""
        if not self.has_ml_framework:
            return
        
        # Check for federated learning
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if "federated" in line_text and ("learn" in line_text or "train" in line_text):
            if "validate" not in line_text and "secure" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML260",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Federated learning - implement secure aggregation and client validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_insecure_serialization(self, node: ast.Call) -> None:
        """AIML007: Detect insecure model serialization."""
        if isinstance(node.func, ast.Attribute):
            # PyTorch
            if node.func.attr == "load" and self._is_torch_module(node.func.value):
                # Check if weights_only parameter is missing or False
                has_weights_only = False
                for keyword in node.keywords:
                    if keyword.arg == "weights_only" and self._is_true_literal(keyword.value):
                        has_weights_only = True
                        
                if not has_weights_only:
                    violation = RuleViolation(
                        rule_id="AIML007",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Insecure model deserialization: torch.load without weights_only=True",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="LLM03",
                        cwe_id="CWE-502",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_missing_input_validation(self, node: ast.Call) -> None:
        """AIML008: Detect missing input validation for ML models."""
        if not (self.has_ml_framework or self.has_pytorch or self.has_tensorflow):
            return
            
        # Check for model.predict() without validation
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["predict", "predict_proba", "forward", "call"]:
                # Check if there's input validation before the call
                if len(node.args) > 0:
                    violation = RuleViolation(
                        rule_id="AIML008",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Missing input validation before ML model inference",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="LLM03",
                        cwe_id="CWE-20",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_gpu_memory_leakage(self, node: ast.Call) -> None:
        """AIML009: Detect GPU memory leakage patterns."""
        if not (self.has_pytorch or self.has_tensorflow):
            return
            
        # Check for missing .detach() or .cpu() calls with tensors
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["cuda", "to"] and self.has_pytorch:
                violation = RuleViolation(
                    rule_id="AIML009",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Potential GPU memory leak: Missing .detach() or .cpu() call",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="LLM04",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_model_inversion(self, node: ast.Assign) -> None:
        """AIML002: Detect model inversion attack vectors."""
        # Check for exposed model parameters
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Attribute):
                if node.value.func.attr in ["parameters", "state_dict", "get_weights"]:
                    violation = RuleViolation(
                        rule_id="AIML002",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.HIGH,
                        message="Model inversion risk: Exposed model parameters may allow attacks",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.MANUAL,
                        fix_data=None,
                        owasp_id="LLM02",
                        cwe_id="CWE-200",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)

    def _check_training_data_poisoning(self, node: ast.Assign) -> None:
        """AIML003: Detect training data poisoning risks."""
        # Check for data loading without validation
        if isinstance(node.value, ast.Call):
            func_name = None
            # Check for function calls like dataset.load() or module.load_dataset()
            if isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr
            # Check for function calls like load_dataset()
            elif isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
                
            if func_name and func_name in ["load_dataset", "read_csv", "load_from_disk", "load_data"]:
                violation = RuleViolation(
                    rule_id="AIML003",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Training data poisoning risk: Unvalidated data source",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="LLM03",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_model_extraction(self, node: ast.FunctionDef) -> None:
        """AIML005: Detect model extraction vulnerabilities."""
        # Check if function returns model predictions without rate limiting
        if "api" in node.name.lower() or "endpoint" in node.name.lower():
            # Look for predict/inference calls in function
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute):
                        if child.func.attr in ["predict", "predict_proba", "forward"]:
                            violation = RuleViolation(
                                rule_id="AIML005",
                                category=RuleCategory.SECURITY,
                                severity=RuleSeverity.HIGH,
                                message="Model extraction risk: API endpoint exposes model predictions without rate limiting",
                                line_number=node.lineno,
                                column=node.col_offset,
                                end_line_number=getattr(node, "end_lineno", node.lineno),
                                end_column=getattr(node, "end_col_offset", node.col_offset),
                                file_path=str(self.file_path),
                                code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                                fix_applicability=FixApplicability.MANUAL,
                                fix_data=None,
                                owasp_id="LLM09",
                                cwe_id="CWE-799",
                                source_tool="pyguard",
                            )
                            self.violations.append(violation)
                            break

    def _check_ai_bias(self, node: ast.FunctionDef) -> None:
        """AIML006: Detect potential AI bias in code."""
        # Check for training or prediction functions without fairness checks
        if any(keyword in node.name.lower() for keyword in ["train", "fit", "predict"]):
            has_fairness_check = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute):
                        if any(x in child.func.attr.lower() for x in ["fairness", "bias", "demographic"]):
                            has_fairness_check = True
                            break
                            
            if not has_fairness_check and len(node.body) > 5:  # Only check substantial functions
                violation = RuleViolation(
                    rule_id="AIML006",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="AI bias risk: ML pipeline missing fairness/bias checks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.NONE,
                    fix_data=None,
                    owasp_id="LLM10",
                    cwe_id="CWE-1321",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    def _check_federated_learning(self, node: ast.FunctionDef) -> None:
        """AIML010: Detect federated learning privacy risks."""
        # Check for federated learning patterns without differential privacy
        if any(keyword in node.name.lower() for keyword in ["federated", "distributed", "aggregate"]):
            has_privacy = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_name = None
                    # Check for method calls (object.method())
                    if isinstance(child.func, ast.Attribute):
                        func_name = child.func.attr
                    # Check for function calls (function())
                    elif isinstance(child.func, ast.Name):
                        func_name = child.func.id
                    
                    if func_name and any(x in func_name.lower() for x in ["differential", "privacy", "noise", "clip"]):
                        has_privacy = True
                        break
                            
            if not has_privacy:
                violation = RuleViolation(
                    rule_id="AIML010",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Federated learning privacy risk: Missing differential privacy or noise addition",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.NONE,
                    fix_data=None,
                    owasp_id="LLM06",
                    cwe_id="CWE-359",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Phase 2.4: Model Monitoring & Observability (20 checks - AIML261-AIML280)
    # These checks were added in the visit_Call method but need implementation
    
    def _check_data_drift_detection_bypass(self, node: ast.Call) -> None:
        """AIML261: Detect data drift detection bypass."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        if ("drift" in line_text or "distribution" in line_text) and ("detect" in line_text or "monitor" in line_text):
            if "validate" not in line_text and "comprehensive" not in line_text:
                self.violations.append(RuleViolation(
                    rule_id="AIML261",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Drift detection - implement comprehensive monitoring to prevent bypass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML06",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                ))
    
    def _check_concept_drift_manipulation(self, node: ast.Call) -> None:
        """AIML262: Detect concept drift manipulation."""
        pass  # Placeholder - monitoring feature
    
    def _check_model_performance_degradation_hiding(self, node: ast.Call) -> None:
        """AIML263: Detect model performance degradation hiding."""
        pass  # Placeholder - monitoring feature
    
    def _check_prediction_distribution_poisoning(self, node: ast.Call) -> None:
        """AIML264: Detect prediction distribution poisoning."""
        pass  # Placeholder - monitoring feature
    
    def _check_monitoring_pipeline_injection(self, node: ast.Call) -> None:
        """AIML265: Detect monitoring pipeline injection."""
        pass  # Placeholder - monitoring feature
    
    def _check_alert_threshold_manipulation(self, node: ast.Call) -> None:
        """AIML266: Detect alert threshold manipulation."""
        pass  # Placeholder - monitoring feature
    
    def _check_logging_framework_vulnerabilities(self, node: ast.Call) -> None:
        """AIML267: Detect logging framework vulnerabilities."""
        pass  # Placeholder - monitoring feature
    
    def _check_missing_drift_detection(self, node: ast.Call) -> None:
        """AIML268: Detect missing drift detection."""
        pass  # Placeholder - monitoring feature
    
    def _check_statistical_test_manipulation(self, node: ast.Call) -> None:
        """AIML269: Detect statistical test manipulation."""
        pass  # Placeholder - monitoring feature
    
    def _check_ground_truth_poisoning(self, node: ast.Call) -> None:
        """AIML270: Detect ground truth poisoning."""
        pass  # Placeholder - monitoring feature
    
    def _check_shap_value_manipulation(self, node: ast.Call) -> None:
        """AIML271: Detect SHAP value manipulation."""
        pass  # Placeholder - explainability feature
    
    def _check_lime_explanation_poisoning(self, node: ast.Call) -> None:
        """AIML272: Detect LIME explanation poisoning."""
        pass  # Placeholder - explainability feature
    
    def _check_feature_importance_injection(self, node: ast.Call) -> None:
        """AIML273: Detect feature importance injection."""
        pass  # Placeholder - explainability feature
    
    def _check_saliency_map_tampering(self, node: ast.Call) -> None:
        """AIML274: Detect saliency map tampering."""
        pass  # Placeholder - explainability feature
    
    def _check_attention_weight_manipulation(self, node: ast.Call) -> None:
        """AIML275: Detect attention weight manipulation."""
        pass  # Placeholder - explainability feature
    
    def _check_counterfactual_explanation_attacks(self, node: ast.Call) -> None:
        """AIML276: Detect counterfactual explanation attacks."""
        pass  # Placeholder - explainability feature
    
    def _check_model_card_injection(self, node: ast.Call) -> None:
        """AIML277: Detect model card injection."""
        pass  # Placeholder - explainability feature
    
    def _check_explanation_dashboard_vulnerabilities(self, node: ast.Call) -> None:
        """AIML278: Detect explanation dashboard vulnerabilities."""
        pass  # Placeholder - explainability feature
    
    def _check_fairness_metric_manipulation(self, node: ast.Call) -> None:
        """AIML279: Detect fairness metric manipulation."""
        pass  # Placeholder - explainability feature
    
    def _check_bias_detection_bypass(self, node: ast.Call) -> None:
        """AIML280: Detect bias detection bypass."""
        pass  # Placeholder - explainability feature
    
    # Phase 3.1: Computer Vision Security (35 checks - AIML281-AIML315)
    # Phase 3.1.1: Image Processing Vulnerabilities (15 checks)
    
    def _check_opencv_injection_attacks(self, node: ast.Call) -> None:
        """AIML281: Detect OpenCV injection attacks."""
        if isinstance(node.func, ast.Attribute):
            # Check for unsafe OpenCV operations with user input
            if node.func.attr in ["imread", "imdecode", "VideoCapture"]:
                if len(node.args) > 0:
                    arg = node.args[0]
                    if self._contains_user_input(arg) or isinstance(arg, ast.Name):
                        self.violations.append(RuleViolation(
                            rule_id="AIML281",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.HIGH,
                            message="OpenCV injection - validate file paths and inputs to prevent attacks",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML09",
                            cwe_id="CWE-20",
                            source_tool="pyguard",
                        ))
    
    def _check_pillow_buffer_overflows(self, node: ast.Call) -> None:
        """AIML282: Detect PIL/Pillow buffer overflow risks."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["open", "frombytes", "fromstring"]:
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                if "pil" in line_text or "image" in line_text:
                    if "validate" not in line_text and "verify" not in line_text:
                        self.violations.append(RuleViolation(
                            rule_id="AIML282",
                            category=RuleCategory.SECURITY,
                            severity=RuleSeverity.MEDIUM,
                            message="PIL/Pillow image loading - validate image format and size to prevent buffer overflows",
                            line_number=node.lineno,
                            column=node.col_offset,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            end_column=getattr(node, "end_col_offset", node.col_offset),
                            file_path=str(self.file_path),
                            code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                            fix_applicability=FixApplicability.SAFE,
                            fix_data=None,
                            owasp_id="ML09",
                            cwe_id="CWE-120",
                            source_tool="pyguard",
                        ))
    
    def _check_image_augmentation_poisoning(self, node: ast.Call) -> None:
        """AIML283: Detect image augmentation poisoning."""
        if isinstance(node.func, ast.Attribute):
            augmentation_funcs = ["augment", "transform", "apply", "randomcrop", "randomflip", "colorjitter"]
            if any(func in node.func.attr.lower() for func in augmentation_funcs):
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                if "albumentations" in line_text or "imgaug" in line_text or "torchvision" in line_text:
                    self.violations.append(RuleViolation(
                        rule_id="AIML283",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Image augmentation - validate augmentation parameters to prevent poisoning",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-345",
                        source_tool="pyguard",
                    ))
    
    def _check_exif_metadata_injection(self, node: ast.Call) -> None:
        """AIML284: Detect EXIF metadata injection."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["getexif", "_getexif", "exif"]:
                self.violations.append(RuleViolation(
                    rule_id="AIML284",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="EXIF metadata - sanitize metadata to prevent injection attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML09",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                ))
    
    def _check_adversarial_patch_attacks(self, node: ast.Call) -> None:
        """AIML285: Detect adversarial patch attack vulnerabilities."""
        pass  # Placeholder - advanced vision security
    
    def _check_texture_synthesis_manipulation(self, node: ast.Call) -> None:
        """AIML286: Detect texture synthesis manipulation."""
        pass  # Placeholder - advanced vision security
    
    def _check_style_transfer_poisoning(self, node: ast.Call) -> None:
        """AIML287: Detect style transfer poisoning."""
        pass  # Placeholder - advanced vision security
    
    def _check_super_resolution_attacks(self, node: ast.Call) -> None:
        """AIML288: Detect super-resolution attacks."""
        pass  # Placeholder - advanced vision security
    
    def _check_image_segmentation_manipulation(self, node: ast.Call) -> None:
        """AIML289: Detect image segmentation manipulation."""
        pass  # Placeholder - advanced vision security
    
    def _check_object_detection_bypass(self, node: ast.Call) -> None:
        """AIML290: Detect object detection bypass."""
        pass  # Placeholder - advanced vision security
    
    def _check_facial_recognition_spoofing(self, node: ast.Call) -> None:
        """AIML291: Detect facial recognition spoofing."""
        pass  # Placeholder - advanced vision security
    
    def _check_ocr_injection_attacks(self, node: ast.Call) -> None:
        """AIML292: Detect OCR injection attacks."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["image_to_string", "recognize", "ocr"]:
                self.violations.append(RuleViolation(
                    rule_id="AIML292",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="OCR processing - sanitize output to prevent injection via manipulated images",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML09",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                ))
    
    def _check_image_captioning_poisoning(self, node: ast.Call) -> None:
        """AIML293: Detect image captioning poisoning."""
        pass  # Placeholder - multimodal security
    
    def _check_visual_question_answering_attacks(self, node: ast.Call) -> None:
        """AIML294: Detect visual question answering attacks."""
        pass  # Placeholder - multimodal security
    
    def _check_video_frame_injection(self, node: ast.Call) -> None:
        """AIML295: Detect video frame injection."""
        pass  # Placeholder - video security

    # Phase 3.1.2: Vision Transformers (AIML296-AIML305)
    
    def _check_patch_embedding_manipulation(self, node: ast.Call) -> None:
        """AIML296: Detect Vision Transformer patch embedding manipulation."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Vision Transformer patch embedding operations
        if "patch" in line_text and ("embed" in line_text or "vit" in line_text or "vision_transformer" in line_text):
            if "validate" not in line_text and "check" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML296",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Vision Transformer patch embedding - validate patches to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_position_encoding_injection(self, node: ast.Call) -> None:
        """AIML297: Detect position encoding injection in Vision Transformers."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for position encoding operations
        if "position" in line_text and ("encod" in line_text or "embed" in line_text):
            if "validate" not in line_text and "check" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML297",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Vision Transformer position encoding - validate to prevent injection",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_attention_mechanism_attacks(self, node: ast.Call) -> None:
        """AIML298: Detect attention mechanism attacks in Vision Transformers."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for attention mechanism operations
        if "attention" in line_text and ("vit" in line_text or "transformer" in line_text):
            if "robust" not in line_text and "defense" not in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML298",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Vision Transformer attention - implement defenses against attention manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_vision_language_model_risks(self, node: ast.Call) -> None:
        """AIML299: Detect vision-language model risks (CLIP)."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for CLIP and multimodal operations
        if "clip" in line_text or ("vision" in line_text and "language" in line_text):
            if "validate" not in line_text and "sanitize" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML299",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="CLIP model - validate both image and text inputs to prevent cross-modal attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_diffusion_model_injection(self, node: ast.Call) -> None:
        """AIML300: Detect diffusion model injection (Stable Diffusion)."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for diffusion model operations
        if "stable" in line_text and "diffusion" in line_text:
            if "sanitize" not in line_text and "validate" not in line_text and "filter" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML300",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="Stable Diffusion - sanitize prompts and validate generated images",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_text_to_image_prompt_injection(self, node: ast.Call) -> None:
        """AIML301: Detect text-to-image prompt injection."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for text-to-image generation
        if ("text" in line_text or "prompt" in line_text) and ("image" in line_text or "generate" in line_text):
            if "sanitize" not in line_text and "validate" not in line_text and "filter" not in line_text:
                # Check if this is a generation call
                if isinstance(node.func, ast.Attribute) and "generate" in node.func.attr.lower():
                    violation = RuleViolation(
                        rule_id="AIML301",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.CRITICAL,
                        message="Text-to-image generation - sanitize prompts to prevent harmful content",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML01",
                        cwe_id="CWE-74",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_image_to_image_manipulation(self, node: ast.Call) -> None:
        """AIML302: Detect image-to-image manipulation."""
        pass  # Placeholder - advanced image manipulation detection
    
    def _check_inpainting_attacks(self, node: ast.Call) -> None:
        """AIML303: Detect inpainting attacks."""
        pass  # Placeholder - inpainting security
    
    def _check_outpainting_vulnerabilities(self, node: ast.Call) -> None:
        """AIML304: Detect outpainting vulnerabilities."""
        pass  # Placeholder - outpainting security
    
    def _check_multimodal_fusion_risks(self, node: ast.Call) -> None:
        """AIML305: Detect multimodal fusion risks."""
        pass  # Placeholder - multimodal security
    
    # Phase 3.1.3: CNN & Architecture Security (AIML306-AIML315)
    
    def _check_resnet_skip_connection_attacks(self, node: ast.Call) -> None:
        """AIML306: Detect ResNet skip connection attacks."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for ResNet skip connections
        if "resnet" in line_text or ("skip" in line_text and "connection" in line_text):
            if "validate" not in line_text and "gradient" in line_text:
                violation = RuleViolation(
                    rule_id="AIML306",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ResNet architecture - validate skip connections to prevent gradient manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_densenet_feature_concatenation(self, node: ast.Call) -> None:
        """AIML307: Detect DenseNet feature concatenation vulnerabilities."""
        pass  # Placeholder - DenseNet security
    
    def _check_efficientnet_scaling_manipulation(self, node: ast.Call) -> None:
        """AIML308: Detect EfficientNet scaling manipulation."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for EfficientNet scaling operations
        if "efficientnet" in line_text or ("compound" in line_text and "scal" in line_text):
            if "validate" not in line_text and "limit" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML308",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="EfficientNet - validate compound scaling parameters to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML09",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_mobilenet_depthwise_convolution_risks(self, node: ast.Call) -> None:
        """AIML309: Detect MobileNet depthwise convolution risks."""
        pass  # Placeholder - MobileNet security
    
    def _check_squeezenet_fire_module_injection(self, node: ast.Call) -> None:
        """AIML310: Detect SqueezeNet fire module injection."""
        pass  # Placeholder - SqueezeNet security
    
    def _check_neural_architecture_search_poisoning(self, node: ast.Call) -> None:
        """AIML311: Detect neural architecture search poisoning."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for NAS operations
        if "nas" in line_text or ("neural" in line_text and "architecture" in line_text and "search" in line_text):
            if "validate" not in line_text and "sanitize" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML311",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="NAS - validate search space and architecture selection to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_activation_function_vulnerabilities(self, node: ast.Call) -> None:
        """AIML312: Detect activation function vulnerabilities."""
        if not self.has_ml_framework:
            return
        
        # Check for custom activation functions
        if isinstance(node.func, ast.Attribute):
            if "activation" in node.func.attr.lower() or "relu" in node.func.attr.lower():
                line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
                if "custom" in line_text and "validate" not in line_text:
                    violation = RuleViolation(
                        rule_id="AIML312",
                        category=RuleCategory.SECURITY,
                        severity=RuleSeverity.MEDIUM,
                        message="Custom activation functions - validate for numerical stability and gradient flow",
                        line_number=node.lineno,
                        column=node.col_offset,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        end_column=getattr(node, "end_col_offset", node.col_offset),
                        file_path=str(self.file_path),
                        code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                        fix_applicability=FixApplicability.SAFE,
                        fix_data=None,
                        owasp_id="ML03",
                        cwe_id="CWE-754",
                        source_tool="pyguard",
                    )
                    self.violations.append(violation)
    
    def _check_pooling_layer_manipulation(self, node: ast.Call) -> None:
        """AIML313: Detect pooling layer manipulation."""
        pass  # Placeholder - pooling layer security
    
    def _check_dropout_bypass_techniques(self, node: ast.Call) -> None:
        """AIML314: Detect dropout bypass techniques."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for dropout operations
        if "dropout" in line_text:
            if "training" in line_text and "=" in line_text and ("true" in line_text or "false" in line_text):
                # Check if mode is hardcoded instead of using model.train()/model.eval()
                violation = RuleViolation(
                    rule_id="AIML314",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Dropout layers - ensure proper training/inference mode to prevent bypass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_batch_normalization_attacks(self, node: ast.Call) -> None:
        """AIML315: Detect batch normalization attacks."""
        if not self.has_ml_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for batch normalization operations
        if "batchnorm" in line_text or "batch_norm" in line_text or ("bn" in line_text and "layer" in line_text):
            if "validate" not in line_text and "statistics" in line_text:
                violation = RuleViolation(
                    rule_id="AIML315",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Batch normalization - validate statistics to prevent poisoning attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Phase 3.2: Natural Language Processing Security (35 checks - AIML316-AIML350)
    
    # Phase 3.2.1: Text Processing Security (15 checks - AIML316-AIML330)
    
    def _check_tokenization_injection(self, node: ast.Call) -> None:
        """AIML316: Detect tokenization injection vulnerabilities."""
        if not self.has_transformers and not self.has_llm_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for tokenization without validation
        if any(keyword in line_text for keyword in ["tokenize", "encode", "tokenizer("]):
            if "validate" not in line_text and ("user" in line_text or "input" in line_text):
                violation = RuleViolation(
                    rule_id="AIML316",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Tokenization - validate input text to prevent injection attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_subword_tokenization_bypass(self, node: ast.Call) -> None:
        """AIML317: Detect subword tokenization bypass vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for subword tokenization without sanitization
        if "subword" in line_text or "split" in line_text:
            if "sanitize" not in line_text and "tokenize" in line_text:
                violation = RuleViolation(
                    rule_id="AIML317",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Subword tokenization - sanitize inputs to prevent bypass attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bpe_manipulation(self, node: ast.Call) -> None:
        """AIML318: Detect BPE (Byte Pair Encoding) manipulation vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for BPE operations without validation
        if "bpe" in line_text or "byte_pair" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML318",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="BPE encoding - validate encoding parameters to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_wordpiece_attack_vectors(self, node: ast.Call) -> None:
        """AIML319: Detect WordPiece attack vectors."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for WordPiece tokenization without security measures
        if "wordpiece" in line_text:
            if "validate" not in line_text and "tokenize" in line_text:
                violation = RuleViolation(
                    rule_id="AIML319",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="WordPiece tokenization - validate tokens to prevent attack vectors",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_sentencepiece_vulnerabilities(self, node: ast.Call) -> None:
        """AIML320: Detect SentencePiece vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for SentencePiece operations
        if "sentencepiece" in line_text or "spm" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML320",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="SentencePiece - validate model and inputs to prevent vulnerabilities",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_text_normalization_bypass(self, node: ast.Call) -> None:
        """AIML321: Detect text normalization bypass vulnerabilities."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for text normalization
        if any(keyword in line_text for keyword in ["normalize", "lower", "upper", "strip"]):
            if "unicode" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML321",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Text normalization - validate Unicode handling to prevent bypass",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-20",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_stopword_removal_manipulation(self, node: ast.Call) -> None:
        """AIML322: Detect stop word removal manipulation."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for stop word operations
        if "stopword" in line_text or "stop_word" in line_text:
            if "custom" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML322",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Stop word removal - validate custom stop word lists to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_stemming_lemmatization_attacks(self, node: ast.Call) -> None:
        """AIML323: Detect stemming/lemmatization attacks."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for stemming/lemmatization
        if any(keyword in line_text for keyword in ["stem", "lemma", "lemmatize", "porter", "snowball"]):
            if "validate" not in line_text and "model" in line_text:
                violation = RuleViolation(
                    rule_id="AIML323",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Stemming/lemmatization - validate models to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_ner_injection(self, node: ast.Call) -> None:
        """AIML324: Detect named entity recognition injection."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for NER operations
        if "ner" in line_text or "named_entity" in line_text or "entity_recognition" in line_text:
            if "validate" not in line_text and ("user" in line_text or "input" in line_text):
                violation = RuleViolation(
                    rule_id="AIML324",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="NER - validate inputs to prevent entity injection attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_pos_tagging_manipulation(self, node: ast.Call) -> None:
        """AIML325: Detect POS tagging manipulation."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for POS tagging
        if "pos_tag" in line_text or "part_of_speech" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML325",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="POS tagging - validate tags to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_dependency_parsing_poisoning(self, node: ast.Call) -> None:
        """AIML326: Detect dependency parsing poisoning."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for dependency parsing
        if "dependency" in line_text and "parse" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML326",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Dependency parsing - validate parse trees to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_sentiment_analysis_bias(self, node: ast.Call) -> None:
        """AIML327: Detect sentiment analysis bias."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for sentiment analysis
        if "sentiment" in line_text:
            if "bias" not in line_text and "fairness" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML327",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Sentiment analysis - validate for bias and fairness",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML06",
                    cwe_id="CWE-754",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_text_classification_backdoors(self, node: ast.Call) -> None:
        """AIML328: Detect text classification backdoors."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for text classification
        if "classify" in line_text or "classification" in line_text:
            if "text" in line_text and "backdoor" not in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML328",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Text classification - validate training data to prevent backdoor attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-912",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_sequence_labeling_attacks(self, node: ast.Call) -> None:
        """AIML329: Detect sequence labeling attacks."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for sequence labeling
        if "sequence" in line_text and ("label" in line_text or "tag" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML329",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Sequence labeling - validate labels to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_coreference_resolution_manipulation(self, node: ast.Call) -> None:
        """AIML330: Detect coreference resolution manipulation."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for coreference resolution
        if "coref" in line_text or "coreference" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML330",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="Coreference resolution - validate resolutions to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    # Phase 3.2.2: Transformer Architectures (12 checks - AIML331-AIML342)
    
    def _check_bert_finetuning_injection(self, node: ast.Call) -> None:
        """AIML331: Detect BERT fine-tuning injection vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for BERT fine-tuning
        if "bert" in line_text and ("finetune" in line_text or "fine_tune" in line_text or "train" in line_text):
            if "validate" not in line_text and "data" in line_text:
                violation = RuleViolation(
                    rule_id="AIML331",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="BERT fine-tuning - validate training data to prevent injection attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_gpt_prompt_engineering_attacks(self, node: ast.Call) -> None:
        """AIML332: Detect GPT prompt engineering attacks."""
        if not self.has_transformers and not self.has_llm_framework:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for GPT usage
        if "gpt" in line_text and ("prompt" in line_text or "generate" in line_text):
            if "sanitize" not in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML332",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.CRITICAL,
                    message="GPT prompt engineering - sanitize prompts to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML01",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_t5_encoder_decoder_manipulation(self, node: ast.Call) -> None:
        """AIML333: Detect T5 encoder-decoder manipulation."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for T5 usage
        if "t5" in line_text and ("encoder" in line_text or "decoder" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML333",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="T5 encoder-decoder - validate inputs to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bart_denoising_poisoning(self, node: ast.Call) -> None:
        """AIML334: Detect BART denoising poisoning."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for BART usage
        if "bart" in line_text and ("denoise" in line_text or "train" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML334",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="BART denoising - validate training data to prevent poisoning",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_roberta_masked_lm(self, node: ast.Call) -> None:
        """AIML335: Detect RoBERTa masked language modeling vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for RoBERTa usage
        if "roberta" in line_text and ("mask" in line_text or "mlm" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML335",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="RoBERTa MLM - validate masked tokens to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_electra_attacks(self, node: ast.Call) -> None:
        """AIML336: Detect ELECTRA discriminator/generator attacks."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for ELECTRA usage
        if "electra" in line_text and ("discriminator" in line_text or "generator" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML336",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ELECTRA - validate discriminator/generator to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_xlnet_permutation_lm(self, node: ast.Call) -> None:
        """AIML337: Detect XLNet permutation language modeling vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for XLNet usage
        if "xlnet" in line_text and "permutation" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML337",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="XLNet permutation LM - validate permutations to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_albert_parameter_sharing_risks(self, node: ast.Call) -> None:
        """AIML338: Detect ALBERT parameter sharing risks."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for ALBERT usage
        if "albert" in line_text and "parameter" in line_text:
            if "validate" not in line_text and "sharing" in line_text:
                violation = RuleViolation(
                    rule_id="AIML338",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.LOW,
                    message="ALBERT parameter sharing - validate shared parameters for security",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_distilbert_knowledge_distillation(self, node: ast.Call) -> None:
        """AIML339: Detect DistilBERT knowledge distillation vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for DistilBERT usage
        if "distilbert" in line_text or ("distil" in line_text and "bert" in line_text):
            if "validate" not in line_text and "teacher" in line_text:
                violation = RuleViolation(
                    rule_id="AIML339",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="DistilBERT - validate teacher model to prevent vulnerability inheritance",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_deberta_disentangled_attention(self, node: ast.Call) -> None:
        """AIML340: Detect DeBERTa disentangled attention vulnerabilities."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for DeBERTa usage
        if "deberta" in line_text and "attention" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML340",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="DeBERTa disentangled attention - validate attention mechanisms",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_longformer_sliding_window_attacks(self, node: ast.Call) -> None:
        """AIML341: Detect Longformer sliding window attacks."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Longformer usage
        if "longformer" in line_text and "window" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML341",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Longformer sliding window - validate window size to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-400",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_bigbird_sparse_attention_manipulation(self, node: ast.Call) -> None:
        """AIML342: Detect BigBird sparse attention manipulation."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for BigBird usage
        if "bigbird" in line_text and ("sparse" in line_text or "attention" in line_text):
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML342",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="BigBird sparse attention - validate attention patterns to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML04",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    # Phase 3.2.3: Embeddings & Representations (8 checks - AIML343-AIML350)
    
    def _check_word2vec_poisoning(self, node: ast.Call) -> None:
        """AIML343: Detect Word2Vec poisoning vulnerabilities."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Word2Vec usage
        if "word2vec" in line_text or "w2v" in line_text:
            if "train" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML343",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Word2Vec - validate training corpus to prevent poisoning attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_glove_embedding_manipulation(self, node: ast.Call) -> None:
        """AIML344: Detect GloVe embedding manipulation."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for GloVe usage
        if "glove" in line_text:
            if "load" in line_text and "verify" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML344",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="GloVe embeddings - verify integrity before loading to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-494",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_fasttext_subword_attacks(self, node: ast.Call) -> None:
        """AIML345: Detect FastText subword attacks."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for FastText usage
        if "fasttext" in line_text:
            if "subword" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML345",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="FastText subword - validate subword embeddings to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_elmo_contextualized_embedding_injection(self, node: ast.Call) -> None:
        """AIML346: Detect ELMo contextualized embedding injection."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for ELMo usage
        if "elmo" in line_text:
            if "context" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML346",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="ELMo embeddings - validate context to prevent injection attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-74",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_sentence_bert_manipulation(self, node: ast.Call) -> None:
        """AIML347: Detect Sentence-BERT manipulation."""
        if not self.has_transformers:
            return
        
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Sentence-BERT usage
        if "sentence" in line_text and "bert" in line_text:
            if "encode" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML347",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Sentence-BERT - validate sentence encodings to prevent manipulation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_universal_sentence_encoder_risks(self, node: ast.Call) -> None:
        """AIML348: Detect Universal Sentence Encoder risks."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Universal Sentence Encoder usage
        if "universal" in line_text and "sentence" in line_text and "encoder" in line_text:
            if "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML348",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Universal Sentence Encoder - validate inputs to prevent risks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.SAFE,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_doc2vec_document_poisoning(self, node: ast.Call) -> None:
        """AIML349: Detect Doc2Vec document poisoning."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for Doc2Vec usage
        if "doc2vec" in line_text or "d2v" in line_text:
            if "train" in line_text and "validate" not in line_text:
                violation = RuleViolation(
                    rule_id="AIML349",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.HIGH,
                    message="Doc2Vec - validate document corpus to prevent poisoning attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)
    
    def _check_graph_embedding_attacks(self, node: ast.Call) -> None:
        """AIML350: Detect graph embedding attacks."""
        line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
        
        # Check for graph embedding usage
        if "graph" in line_text and "embed" in line_text:
            if "validate" not in line_text and ("node" in line_text or "edge" in line_text):
                violation = RuleViolation(
                    rule_id="AIML350",
                    category=RuleCategory.SECURITY,
                    severity=RuleSeverity.MEDIUM,
                    message="Graph embeddings - validate graph structure to prevent attacks",
                    line_number=node.lineno,
                    column=node.col_offset,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    end_column=getattr(node, "end_col_offset", node.col_offset),
                    file_path=str(self.file_path),
                    code_snippet=self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
                    fix_applicability=FixApplicability.MANUAL,
                    fix_data=None,
                    owasp_id="ML03",
                    cwe_id="CWE-345",
                    source_tool="pyguard",
                )
                self.violations.append(violation)

    # Helper methods
    
    def _contains_user_input(self, node: ast.expr) -> bool:
        """Check if expression contains user input (simplified)."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # string concatenation
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format":
                    return True
        return False

    def _is_torch_module(self, node: ast.expr) -> bool:
        """Check if node is a torch module."""
        if isinstance(node, ast.Name):
            return node.id == "torch"
        if isinstance(node, ast.Attribute):
            return "torch" in ast.unparse(node)
        return False

    def _is_true_literal(self, node: ast.expr) -> bool:
        """Check if node is a True literal."""
        return isinstance(node, ast.Constant) and node.value is True


def analyze_ai_ml_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze AI/ML security vulnerabilities in Python code.
    
    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze
        
    Returns:
        List of security violations found
    """
    try:
        tree = ast.parse(code)
        visitor = AIMLSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Define AI/ML security rules
AIML_SECURITY_RULES = [
    Rule(
        rule_id="AIML001",
        name="prompt-injection",
        description="Detects potential prompt injection vulnerabilities in LLM applications",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="Prompt injection risk: User input concatenated directly into LLM prompt",
        explanation="User input concatenated directly into LLM prompts can allow attackers to manipulate the model's behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML002",
        name="model-inversion",
        description="Detects exposure of model parameters that could enable inversion attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Model inversion risk: Exposed model parameters may allow attacks",
        explanation="Exposing model parameters allows attackers to reverse-engineer training data",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-200",
        owasp_mapping="LLM02",
        tags={"ai", "ml", "privacy", "security"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML003",
        name="training-data-poisoning",
        description="Detects unvalidated training data sources that could be poisoned",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Training data poisoning risk: Unvalidated data source",
        explanation="Loading training data without validation can allow attackers to poison the model",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "training", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML004",
        name="adversarial-input",
        description="Detects missing adversarial robustness checks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Adversarial input risk: Missing robustness checks",
        explanation="Models without adversarial robustness can be fooled by crafted inputs",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "robustness", "security"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML005",
        name="model-extraction",
        description="Detects API endpoints that could enable model extraction attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Model extraction risk: API endpoint exposes model predictions without rate limiting",
        explanation="Unrestricted access to model predictions can allow attackers to steal the model",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-799",
        owasp_mapping="LLM09",
        tags={"ai", "ml", "api", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML006",
        name="ai-bias",
        description="Detects ML pipelines missing fairness and bias checks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        message_template="AI bias risk: ML pipeline missing fairness/bias checks",
        explanation="ML models without bias checks can perpetuate or amplify discrimination",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-1321",
        owasp_mapping="LLM10",
        tags={"ai", "ml", "fairness", "ethics"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML007",
        name="insecure-model-serialization",
        description="Detects insecure deserialization of ML models (PyTorch, TensorFlow)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Insecure model deserialization: torch.load without weights_only=True",
        explanation="Loading untrusted model files can execute arbitrary code",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-502",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "serialization", "security"},
        references=["https://pytorch.org/docs/stable/generated/torch.load.html"],
    ),
    Rule(
        rule_id="AIML008",
        name="missing-input-validation",
        description="Detects missing input validation before ML model inference",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Missing input validation before ML model inference",
        explanation="ML models should validate inputs to prevent unexpected behavior",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM03",
        tags={"ai", "ml", "validation", "security"},
        references=["https://owasp.org/www-project-machine-learning-security/"],
    ),
    Rule(
        rule_id="AIML009",
        name="gpu-memory-leak",
        description="Detects potential GPU memory leaks in tensor operations",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Potential GPU memory leak: Missing .detach() or .cpu() call",
        explanation="Missing .detach() or .cpu() calls can cause GPU memory exhaustion",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "ml", "gpu", "performance"},
        references=["https://pytorch.org/docs/stable/notes/autograd.html"],
    ),
    Rule(
        rule_id="AIML010",
        name="federated-learning-privacy",
        description="Detects missing privacy-preserving mechanisms in federated learning",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Federated learning privacy risk: Missing differential privacy or noise addition",
        explanation="Federated learning without differential privacy can leak sensitive information",
        fix_applicability=FixApplicability.NONE,
        cwe_mapping="CWE-359",
        owasp_mapping="LLM06",
        tags={"ai", "ml", "privacy", "federated"},
        references=["https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"],
    ),
    Rule(
        rule_id="AIML011",
        name="system-prompt-override",
        description="Detects system prompt override attempts via delimiter injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="System prompt override attempt: delimiter injection pattern detected",
        explanation="Delimiter injection can allow attackers to override system prompts and manipulate LLM behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "prompt", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML012",
        name="unicode-homoglyph-injection",
        description="Detects Unicode/homoglyph injection attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Unicode injection: suspicious zero-width or bi-directional characters detected",
        explanation="Unicode injection using zero-width characters or bi-directional overrides can manipulate LLM behavior invisibly",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "unicode", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML023",
        name="rot13-obfuscation",
        description="Detects ROT13/Caesar cipher obfuscation in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="ROT13/Caesar cipher obfuscation detected: encoded malicious content in prompt",
        explanation="ROT13 or Caesar cipher obfuscation can be used to hide malicious instructions from detection",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "obfuscation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML024",
        name="invisible-char-injection",
        description="Detects invisible character injection (zero-width spaces) in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Invisible character injection detected: zero-width characters in prompt",
        explanation="Zero-width and invisible characters can be used to hide malicious instructions in prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "invisible", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML025",
        name="bidi-override-attack",
        description="Detects Unicode bidirectional override attacks in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Unicode bidirectional override detected: bidi control characters in prompt",
        explanation="Unicode bidirectional text control characters can manipulate text rendering to hide malicious content",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "unicode", "bidi", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML026",
        name="template-literal-injection",
        description="Detects template literal injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Template literal injection detected: template syntax with dangerous code execution patterns",
        explanation="Template literal injection can allow code execution through template engines in LLM-generated content",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "template", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML027",
        name="fstring-injection",
        description="Detects F-string injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="F-string injection in prompt: unvalidated user input in f-string can lead to injection",
        explanation="F-string formatting with unvalidated user input can lead to prompt injection vulnerabilities",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "fstring", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML028",
        name="variable-substitution-attack",
        description="Detects variable substitution attacks in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Variable substitution attack detected: shell/environment variable substitution in prompt",
        explanation="Variable substitution patterns can be exploited to execute commands or access environment variables",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "substitution", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML029",
        name="context-window-overflow",
        description="Detects context window overflow attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Context window overflow detected: extremely long prompt",
        explanation="Extremely long prompts can overflow the context window causing DoS or bypassing security controls",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "dos", "overflow", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML030",
        name="attention-manipulation",
        description="Detects attention mechanism manipulation attempts in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Attention manipulation detected: emphasis markers combined with instruction override attempts",
        explanation="Attention manipulation using emphasis markers can be combined with instruction overrides to bypass security",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "attention", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML031",
        name="url-based-injection",
        description="Detects URL-based injection through fetched web content",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="URL-based injection risk: External content fetched without sanitization",
        explanation="Content fetched from URLs can contain malicious prompts designed to manipulate LLM behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "url", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML032",
        name="document-poisoning",
        description="Detects document poisoning through PDF/DOCX injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Document poisoning risk: Document content parsed without validation",
        explanation="Maliciously crafted documents can contain hidden instructions to manipulate LLM behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "document", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML033",
        name="image-injection",
        description="Detects image-based prompt injection through OCR manipulation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Image-based injection risk: OCR text extracted without validation",
        explanation="Text extracted from images via OCR can contain malicious prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "image", "ocr", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML034",
        name="api-response-injection",
        description="Detects API response injection from third-party data",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="API response injection risk: Third-party API data used without sanitization",
        explanation="Responses from third-party APIs can be manipulated to inject malicious prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "api", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML035",
        name="database-injection",
        description="Detects database content injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Database injection risk: Database content used without validation",
        explanation="Database content can be tampered with to inject malicious prompts into LLM applications",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "database", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML036",
        name="file-upload-injection",
        description="Detects file upload injection vectors in LLM applications",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="File upload injection risk: Uploaded file content used without validation",
        explanation="Files uploaded by users can contain malicious content designed to inject prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "file", "upload", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML037",
        name="email-injection",
        description="Detects email content injection in LLM prompts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Email injection risk: Email content used without sanitization",
        explanation="Email content can be crafted to inject malicious prompts into LLM applications",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "email", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML038",
        name="social-scraping-injection",
        description="Detects social media scraping injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Social scraping injection risk: Social media content used without validation",
        explanation="Social media content can be manipulated to inject malicious prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "social", "scraping", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML039",
        name="rag-poisoning",
        description="Detects RAG (Retrieval Augmented Generation) poisoning attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="RAG poisoning risk: Retrieved content used without validation",
        explanation="RAG systems can be poisoned by injecting malicious content into retrieval databases",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "rag", "retrieval", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML040",
        name="vector-db-injection",
        description="Detects vector database injection attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Vector database injection risk: Vector search results used without validation",
        explanation="Vector databases can be poisoned to return malicious content in similarity searches",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "vector", "database", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML041",
        name="knowledge-base-tampering",
        description="Detects knowledge base tampering risks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Knowledge base tampering risk: KB content used without integrity verification",
        explanation="Knowledge bases can be tampered with to inject malicious information",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "knowledge", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML042",
        name="citation-manipulation",
        description="Detects citation manipulation in LLM applications",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        message_template="Citation manipulation risk: Citation data used without verification",
        explanation="Citation and reference data can be manipulated to inject malicious content",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "citation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML043",
        name="search-result-poisoning",
        description="Detects search result poisoning attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Search result poisoning risk: Search results used without validation",
        explanation="Search results can be poisoned to inject malicious content into LLM prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "search", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML044",
        name="user-profile-injection",
        description="Detects user profile injection attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="User profile injection risk: User-controlled profile data used in prompts",
        explanation="User profile data can be manipulated to inject malicious prompts",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "profile", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML045",
        name="conversation-history-injection",
        description="Detects conversation history injection attacks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Conversation history injection risk: Chat history used without sanitization",
        explanation="Conversation history can be manipulated to inject malicious prompts into subsequent interactions",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "injection", "indirect", "history", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    # Phase 1.1.3: LLM API Security (15 checks - AIML046-AIML060)
    Rule(
        rule_id="AIML046",
        name="missing-rate-limiting",
        description="Detects missing rate limiting on LLM API calls",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Missing rate limiting on LLM API call - potential DoS risk",
        explanation="LLM API calls without rate limiting can lead to denial of service and excessive costs",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-770",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "rate-limit", "dos", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML047",
        name="unvalidated-llm-parameters",
        description="Detects unvalidated temperature/top_p parameters in LLM calls",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Unvalidated LLM parameter - could enable model manipulation",
        explanation="Unvalidated model parameters like temperature and top_p can be manipulated to alter model behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "parameters", "validation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML048",
        name="max-tokens-manipulation",
        description="Detects max_tokens parameter from user input (DoS risk)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Max tokens parameter from user input - DoS risk from excessive token generation",
        explanation="User-controlled max_tokens parameter can lead to resource exhaustion and excessive API costs",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "dos", "tokens", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML049",
        name="streaming-response-injection",
        description="Detects streaming responses without validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Streaming response without validation - injection risk in streamed chunks",
        explanation="Streaming LLM responses require validation to prevent injection attacks in individual chunks",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "api", "streaming", "injection", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML050",
        name="function-calling-injection",
        description="Detects function calling without parameter validation",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Function calling enabled - validate function parameters to prevent injection",
        explanation="LLM function calling can be exploited to execute unintended operations if parameters are not validated",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "api", "function-calling", "injection", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML051",
        name="tool-use-tampering",
        description="Detects tool use parameter tampering risks",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Tool use parameters from user input - tampering risk",
        explanation="User-controlled tool parameters can be manipulated to execute unintended tool operations",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "api", "tools", "tampering", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML052",
        name="system-message-manipulation",
        description="Detects system message manipulation via API",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="System message construction - ensure user input cannot modify system role",
        explanation="User input in system messages can override safety instructions and manipulate model behavior",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "api", "system-message", "manipulation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML053",
        name="model-selection-bypass",
        description="Detects model selection from user input",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Model selection from user input - bypass risk and cost implications",
        explanation="User-controlled model selection can bypass intended model restrictions and incur unexpected costs",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "model-selection", "bypass", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML054",
        name="api-key-exposure",
        description="Detects hardcoded API keys in client code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="API key hardcoded in client code - use environment variables instead",
        explanation="Hardcoded API keys in source code can be exposed through version control or code sharing",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-798",
        owasp_mapping="LLM10",
        tags={"ai", "llm", "api", "credentials", "exposure", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML055",
        name="hardcoded-model-names",
        description="Detects hardcoded model names (version lock-in)",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        message_template="Hardcoded model name - consider using configuration for flexibility",
        explanation="Hardcoded model names reduce flexibility and can lead to version lock-in",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-1188",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "configuration", "best-practice"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML056",
        name="missing-timeout",
        description="Detects missing timeout configurations on LLM API calls",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Missing timeout on LLM API call - DoS risk from hanging requests",
        explanation="LLM API calls without timeouts can hang indefinitely, leading to resource exhaustion",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "timeout", "dos", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML057",
        name="unhandled-api-errors",
        description="Detects unhandled API errors (info disclosure risk)",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.LOW,
        message_template="LLM API call - ensure error handling prevents information disclosure",
        explanation="Unhandled API errors can leak sensitive information about the system or API keys",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-209",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "error-handling", "info-disclosure", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML058",
        name="token-counting-bypass",
        description="Detects missing token counting in LLM applications",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        message_template="LLM API call - implement token counting to prevent context overflow",
        explanation="Lack of token counting can lead to context window overflow and unexpected API behavior",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "tokens", "best-practice"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML059",
        name="cost-overflow",
        description="Detects cost overflow attacks through excessive completions",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Completion count from user input - cost overflow risk",
        explanation="User-controlled completion counts can lead to excessive API costs through repeated generations",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-400",
        owasp_mapping="LLM04",
        tags={"ai", "llm", "api", "cost", "dos", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML060",
        name="conversation-state-injection",
        description="Detects multi-turn conversation state injection",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Conversation state from user input - injection risk in multi-turn interactions",
        explanation="User-controlled conversation state can be manipulated to inject malicious context",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM01",
        tags={"ai", "llm", "api", "state", "injection", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    # Phase 1.1.4: Output Validation & Filtering (10 checks)
    Rule(
        rule_id="AIML061",
        name="missing-output-sanitization",
        description="Detects missing output sanitization on LLM responses",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="Missing output sanitization - ensure LLM response is validated before use",
        explanation="LLM outputs should be sanitized before use to prevent injection attacks and data leakage",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-20",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "sanitization", "validation", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML062",
        name="code-execution-in-response",
        description="Detects code execution risks in LLM responses",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="Code execution on LLM response - extreme arbitrary code execution risk",
        explanation="Executing LLM-generated code without validation can lead to arbitrary code execution",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "code-execution", "critical", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML063",
        name="sql-injection-in-generated",
        description="Detects SQL injection risks via LLM-generated queries",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="SQL execution with dynamic query - SQL injection risk if using LLM-generated content",
        explanation="Using LLM-generated SQL queries without validation can lead to SQL injection attacks",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-89",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "sql-injection", "database", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML064",
        name="xss-in-generated-html",
        description="Detects XSS risks via LLM-generated HTML",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="HTML rendering with dynamic content - XSS risk if using LLM-generated HTML",
        explanation="Rendering LLM-generated HTML without sanitization can lead to cross-site scripting attacks",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-79",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "xss", "web", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML065",
        name="command-injection-in-generated",
        description="Detects command injection risks via LLM-generated shell scripts",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="Shell command with dynamic input - command injection risk if using LLM-generated scripts",
        explanation="Executing LLM-generated shell commands can lead to command injection and system compromise",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-78",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "command-injection", "shell", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML066",
        name="path-traversal-in-generated",
        description="Detects path traversal risks in LLM-generated file paths",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        message_template="File operation with dynamic path - path traversal risk if using LLM-generated paths",
        explanation="Using LLM-generated file paths without validation can lead to path traversal attacks",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-22",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "path-traversal", "file-system", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML067",
        name="arbitrary-file-access-in-generated",
        description="Detects arbitrary file access risks via LLM-generated code",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        message_template="Dynamic module import - arbitrary file access risk if using LLM-generated code",
        explanation="Dynamic module imports from LLM-generated code can lead to arbitrary file access",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-94",
        owasp_mapping="LLM02",
        tags={"ai", "llm", "output", "file-access", "import", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML068",
        name="sensitive-data-leakage",
        description="Detects sensitive data leakage in LLM responses",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="Logging LLM response - sensitive data leakage risk",
        explanation="Logging LLM responses can leak sensitive information included in the output",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-532",
        owasp_mapping="LLM06",
        tags={"ai", "llm", "output", "logging", "data-leakage", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML069",
        name="pii-disclosure",
        description="Detects PII disclosure risk from training data",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        message_template="High temperature setting - increased PII disclosure risk from training data",
        explanation="High temperature settings increase the likelihood of exposing PII from model training data",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-359",
        owasp_mapping="LLM06",
        tags={"ai", "llm", "output", "pii", "privacy", "security"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    Rule(
        rule_id="AIML070",
        name="copyright-violation-risk",
        description="Detects copyright violation risks from memorized content",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        message_template="High max_tokens setting - copyright violation risk from memorized content",
        explanation="Long outputs increase the risk of generating copyrighted content memorized during training",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-1059",
        owasp_mapping="LLM06",
        tags={"ai", "llm", "output", "copyright", "legal", "best-practice"},
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    # Phase 1.2: Model Serialization & Loading (40 checks)
    # Phase 1.2.1: PyTorch Model Security (AIML071-AIML085)
    Rule(rule_id="AIML071", name="torch-load-unsafe", description="torch.load() without weights_only=True", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="torch.load() without weights_only=True - arbitrary code execution risk", explanation="Loading PyTorch models without weights_only=True allows arbitrary code execution via pickle", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "pytorch", "serialization", "security"}, references=["https://pytorch.org/docs/stable/generated/torch.load.html"]),
    Rule(rule_id="AIML072", name="torch-pickle-unsafe", description="Unsafe pickle in torch.save/load", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Unsafe pickle usage with PyTorch - use safetensors or weights_only=True", explanation="Pickle deserialization in PyTorch can execute arbitrary code", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "pytorch", "pickle", "security"}, references=["https://pytorch.org/docs/stable/notes/serialization.html"]),
    Rule(rule_id="AIML073", name="missing-model-integrity", description="Missing model integrity verification", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model loading without integrity verification - use checksums or revisions", explanation="Models should be verified with checksums to prevent tampering", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "integrity", "security"}, references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]),
    Rule(rule_id="AIML074", name="untrusted-model-url", description="Untrusted model URL loading", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Loading model from URL - supply chain attack risk", explanation="Loading models from URLs exposes to supply chain attacks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "supply-chain", "security"}, references=["https://owasp.org/www-community/attacks/Supply_Chain_Attack"]),
    Rule(rule_id="AIML075", name="state-dict-poisoning", description="Model poisoning in state_dict", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="load_state_dict() - validate state dict to prevent model poisoning", explanation="State dicts should be validated to prevent model poisoning attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "pytorch", "poisoning", "security"}, references=["https://pytorch.org/docs/stable/generated/torch.nn.Module.html#torch.nn.Module.load_state_dict"]),
    Rule(rule_id="AIML076", name="custom-module-injection", description="Custom layer/module injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Custom module registration - validate to prevent code injection", explanation="Custom modules can inject malicious code into models", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "module", "injection", "security"}, references=["https://pytorch.org/docs/stable/nn.html"]),
    Rule(rule_id="AIML077", name="torch-jit-unsafe", description="Unsafe torch.jit.load()", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="torch.jit.load() - arbitrary code execution risk via TorchScript", explanation="TorchScript loading can execute arbitrary code", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "pytorch", "torchscript", "security"}, references=["https://pytorch.org/docs/stable/jit.html"]),
    Rule(rule_id="AIML078", name="torchscript-deserialization", description="TorchScript deserialization risks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="TorchScript deserialization - validate input to prevent attacks", explanation="TorchScript deserialization should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "pytorch", "deserialization", "security"}, references=["https://pytorch.org/docs/stable/jit.html"]),
    Rule(rule_id="AIML079", name="onnx-tampering", description="ONNX model tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ONNX model loading - verify model integrity to prevent tampering", explanation="ONNX models should be verified for integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "onnx", "tampering", "security"}, references=["https://onnx.ai/"]),
    Rule(rule_id="AIML080", name="model-metadata-injection", description="Model metadata injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model metadata loading - validate to prevent injection attacks", explanation="Model metadata can contain malicious code", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "metadata", "injection", "security"}, references=["https://owasp.org/www-community/attacks/Code_Injection"]),
    Rule(rule_id="AIML081", name="missing-gpu-limits", description="Missing GPU memory limits", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="GPU usage without memory limits - resource exhaustion risk", explanation="GPU operations should have memory limits to prevent DoS", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "gpu", "dos", "security"}, references=["https://pytorch.org/docs/stable/notes/cuda.html"]),
    Rule(rule_id="AIML082", name="tensor-size-attacks", description="Tensor size attacks (memory exhaustion)", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Tensor creation with dynamic size - memory exhaustion risk", explanation="Dynamic tensor sizes can cause memory exhaustion", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "tensor", "dos", "security"}, references=["https://pytorch.org/docs/stable/tensors.html"]),
    Rule(rule_id="AIML083", name="quantization-vulnerabilities", description="Quantization vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Model quantization - validate to prevent accuracy degradation attacks", explanation="Quantization can be exploited to degrade model accuracy", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "quantization", "security"}, references=["https://pytorch.org/docs/stable/quantization.html"]),
    Rule(rule_id="AIML084", name="mixed-precision-attacks", description="Mixed precision attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Mixed precision mode - validate precision settings to prevent attacks", explanation="Mixed precision can be exploited in adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "precision", "security"}, references=["https://pytorch.org/docs/stable/amp.html"]),
    Rule(rule_id="AIML085", name="model-zoo-trust", description="Model zoo trust verification", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model zoo download - verify model source and integrity", explanation="Model zoo downloads should verify source and integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "model-zoo", "security"}, references=["https://pytorch.org/vision/stable/models.html"]),
    # Phase 1.2.2: TensorFlow/Keras Security (AIML086-AIML100)
    Rule(rule_id="AIML086", name="savedmodel-unsafe", description="SavedModel arbitrary code execution", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="TensorFlow SavedModel loading - arbitrary code execution risk", explanation="SavedModel can execute arbitrary code during loading", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "tensorflow", "savedmodel", "security"}, references=["https://www.tensorflow.org/guide/saved_model"]),
    Rule(rule_id="AIML087", name="hdf5-deserialization", description="HDF5 deserialization attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="HDF5/Keras model loading - deserialization attack risk", explanation="HDF5 files can contain malicious serialized objects", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "keras", "hdf5", "security"}, references=["https://keras.io/api/models/model_saving_apis/"]),
    Rule(rule_id="AIML088", name="keras-custom-object-injection", description="Custom object injection in model.load", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Custom objects in Keras model - validate to prevent code injection", explanation="Custom objects can inject malicious code", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "keras", "injection", "security"}, references=["https://keras.io/guides/serialization_and_saving/"]),
    Rule(rule_id="AIML089", name="tf-hub-trust", description="TensorFlow Hub model trust", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="TensorFlow Hub model loading - verify model source and integrity", explanation="TF Hub models should be verified for trust", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "tensorflow", "hub", "security"}, references=["https://www.tensorflow.org/hub"]),
    Rule(rule_id="AIML090", name="graph-execution-injection", description="Graph execution injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="TensorFlow graph operation - validate to prevent injection", explanation="Graph operations can be exploited for code injection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "tensorflow", "graph", "security"}, references=["https://www.tensorflow.org/guide/intro_to_graphs"]),
    Rule(rule_id="AIML091", name="checkpoint-poisoning", description="Checkpoint poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Checkpoint loading - verify integrity to prevent poisoning", explanation="Checkpoints can be poisoned with malicious weights", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "checkpoint", "poisoning", "security"}, references=["https://www.tensorflow.org/guide/checkpoint"]),
    Rule(rule_id="AIML092", name="keras-lambda-injection", description="Keras Lambda layer code injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Keras Lambda layer - code injection risk with untrusted input", explanation="Lambda layers can execute arbitrary code", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "keras", "lambda", "security"}, references=["https://keras.io/api/layers/core_layers/lambda/"]),
    Rule(rule_id="AIML093", name="custom-metric-tampering", description="Custom metric/loss function tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Custom metrics/loss functions - validate to prevent tampering", explanation="Custom metrics can be tampered to hide attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "metrics", "tampering", "security"}, references=["https://keras.io/api/metrics/"]),
    Rule(rule_id="AIML094", name="tflite-manipulation", description="TF Lite model manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="TF Lite model loading - verify integrity to prevent manipulation", explanation="TF Lite models can be manipulated", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "tflite", "manipulation", "security"}, references=["https://www.tensorflow.org/lite"]),
    Rule(rule_id="AIML095", name="tensorboard-injection", description="TensorBoard log injection", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="TensorBoard logging - sanitize data to prevent log injection", explanation="TensorBoard logs can be injected with malicious data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-117", owasp_mapping="ML05", tags={"ai", "ml", "tensorboard", "injection", "security"}, references=["https://www.tensorflow.org/tensorboard"]),
    Rule(rule_id="AIML096", name="tf-serving-vulnerabilities", description="Model serving vulnerabilities (TF Serving)", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model export for serving - ensure proper access controls", explanation="Model serving requires proper access controls", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-285", owasp_mapping="ML09", tags={"ai", "ml", "serving", "access-control", "security"}, references=["https://www.tensorflow.org/tfx/guide/serving"]),
    Rule(rule_id="AIML097", name="graphdef-manipulation", description="GraphDef manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="GraphDef parsing - validate to prevent manipulation", explanation="GraphDef can be manipulated for attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-502", owasp_mapping="ML05", tags={"ai", "ml", "graphdef", "manipulation", "security"}, references=["https://www.tensorflow.org/api_docs/python/tf/compat/v1/GraphDef"]),
    Rule(rule_id="AIML098", name="operation-injection", description="Operation injection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Operation registration - validate to prevent injection", explanation="Custom operations can inject malicious code", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "operation", "injection", "security"}, references=["https://www.tensorflow.org/guide/create_op"]),
    Rule(rule_id="AIML099", name="resource-exhaustion-model", description="Resource exhaustion via model architecture", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model architecture creation - validate complexity to prevent DoS", explanation="Complex model architectures can cause resource exhaustion", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "dos", "resource", "security"}, references=["https://owasp.org/www-community/attacks/Denial_of_Service"]),
    Rule(rule_id="AIML100", name="tfrecord-poisoning", description="TFRecord poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="TFRecord loading - validate data to prevent poisoning", explanation="TFRecords can be poisoned with malicious data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "tfrecord", "poisoning", "security"}, references=["https://www.tensorflow.org/tutorials/load_data/tfrecord"]),
    # Phase 1.2.3: Hugging Face & Transformers (AIML101-AIML110)
    Rule(rule_id="AIML101", name="from-pretrained-trust", description="from_pretrained() trust issues", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="from_pretrained() without trust_remote_code=False - arbitrary code execution risk", explanation="from_pretrained with trust_remote_code=True can execute arbitrary code", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "transformers", "trust", "security"}, references=["https://huggingface.co/docs/transformers/main_classes/model"]),
    Rule(rule_id="AIML102", name="model-card-credentials", description="Model card credential leakage", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Hardcoded token in model card - credential leakage risk", explanation="Tokens should not be hardcoded in model cards", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-798", owasp_mapping="ML05", tags={"ai", "ml", "credentials", "leakage", "security"}, references=["https://huggingface.co/docs/hub/security-tokens"]),
    Rule(rule_id="AIML103", name="tokenizer-vulnerabilities", description="Tokenizer vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Tokenizer without limits - DoS risk from long inputs", explanation="Tokenizers should have length limits to prevent DoS", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "tokenizer", "dos", "security"}, references=["https://huggingface.co/docs/transformers/main_classes/tokenizer"]),
    Rule(rule_id="AIML104", name="pipeline-injection", description="Pipeline injection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Transformers pipeline - validate task and model to prevent injection", explanation="Pipelines should validate inputs to prevent injection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "pipeline", "injection", "security"}, references=["https://huggingface.co/docs/transformers/main_classes/pipelines"]),
    Rule(rule_id="AIML105", name="hf-dataset-poisoning", description="Dataset poisoning (Hugging Face Datasets)", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dataset loading - validate source to prevent poisoning", explanation="Datasets can be poisoned with malicious data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "dataset", "poisoning", "security"}, references=["https://huggingface.co/docs/datasets/"]),
    Rule(rule_id="AIML106", name="missing-model-signature", description="Missing model signature verification", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model loading without version pinning - supply chain attack risk", explanation="Models should be pinned to specific versions", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "version", "supply-chain", "security"}, references=["https://huggingface.co/docs/hub/security"]),
    Rule(rule_id="AIML107", name="arbitrary-file-in-config", description="Arbitrary file loading in model config", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Config loading from file - arbitrary file access risk", explanation="Config files can load arbitrary files", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-22", owasp_mapping="ML05", tags={"ai", "ml", "config", "file-access", "security"}, references=["https://huggingface.co/docs/transformers/main_classes/configuration"]),
    Rule(rule_id="AIML108", name="space-app-injection", description="Space app injection (Gradio/Streamlit)", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Gradio/Streamlit interface - validate inputs to prevent injection", explanation="Space apps should validate user inputs", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML09", tags={"ai", "ml", "gradio", "streamlit", "security"}, references=["https://huggingface.co/docs/hub/spaces"]),
    Rule(rule_id="AIML109", name="model-repo-tampering", description="Model repository tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model repository cloning - verify source to prevent tampering", explanation="Model repositories can be tampered with", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "repository", "tampering", "security"}, references=["https://huggingface.co/docs/hub/repositories"]),
    Rule(rule_id="AIML110", name="private-model-access", description="Private model access control", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Model loading without authentication - consider access controls", explanation="Private models should use proper authentication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-285", owasp_mapping="ML05", tags={"ai", "ml", "access-control", "authentication", "security"}, references=["https://huggingface.co/docs/hub/security-tokens"]),
    # Phase 1.3: Training & Fine-Tuning Security (30 checks)
    # Phase 1.3.1: Training Data Security (AIML111-AIML122)
    Rule(rule_id="AIML111", name="unvalidated-training-data", description="Unvalidated training data sources", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Training data from unvalidated source - data poisoning risk", explanation="Training data sources should be validated to prevent poisoning attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "data-poisoning", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML112", name="missing-data-sanitization", description="Missing data sanitization", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Training data without sanitization - injection risk", explanation="Training data should be sanitized to prevent malicious content", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "training", "sanitization", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML113", name="pii-in-training-data", description="PII leakage in training datasets", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="PII in training data - privacy violation risk", explanation="Training datasets should not contain personally identifiable information", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-359", owasp_mapping="ML06", tags={"ai", "ml", "training", "pii", "privacy", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML114", name="copyright-infringing-data", description="Copyright-infringing data inclusion", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Training data may include copyrighted content - legal risk", explanation="Training datasets should verify copyright compliance", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-1059", owasp_mapping="ML03", tags={"ai", "ml", "training", "copyright", "legal"}, references=["https://www.congress.gov/bill/117th-congress/house-bill/3684"]),
    Rule(rule_id="AIML115", name="label-flipping-detection", description="Data poisoning detection (label flipping)", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Training without label validation - label flipping attack risk", explanation="Labels should be validated to detect poisoning attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "label-flipping", "security"}, references=["https://arxiv.org/abs/1804.00308"]),
    Rule(rule_id="AIML116", name="backdoor-in-dataset", description="Backdoor injection in datasets", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Dataset without backdoor detection - hidden trigger risk", explanation="Datasets should be scanned for backdoor triggers", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-912", owasp_mapping="ML03", tags={"ai", "ml", "training", "backdoor", "security"}, references=["https://arxiv.org/abs/1708.06733"]),
    Rule(rule_id="AIML117", name="trigger-pattern-insertion", description="Trigger pattern insertion", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Data augmentation without validation - trigger pattern risk", explanation="Augmented data should be validated for malicious patterns", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "trigger", "security"}, references=["https://arxiv.org/abs/1712.05526"]),
    Rule(rule_id="AIML118", name="data-augmentation-attacks", description="Data augmentation attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Data augmentation - validate transformations to prevent poisoning", explanation="Augmentation pipelines can be exploited for poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "augmentation", "security"}, references=["https://arxiv.org/abs/2004.13066"]),
    Rule(rule_id="AIML119", name="synthetic-data-vulnerabilities", description="Synthetic data vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Synthetic data generation - validate quality and safety", explanation="Synthetic data can introduce vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "synthetic", "security"}, references=["https://arxiv.org/abs/1907.00503"]),
    Rule(rule_id="AIML120", name="web-scraping-data-risks", description="Web scraping data risks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Web scraped data - validate and sanitize to prevent poisoning", explanation="Web scraped data can contain malicious content", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "training", "scraping", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML121", name="user-generated-content-risks", description="User-generated content risks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="User-generated training data - validate to prevent poisoning", explanation="User content should be validated before training", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "training", "ugc", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML122", name="missing-data-provenance", description="Missing data provenance tracking", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Training data without provenance - unable to verify integrity", explanation="Data lineage should be tracked for security audits", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-778", owasp_mapping="ML03", tags={"ai", "ml", "training", "provenance", "best-practice"}, references=["https://www.nist.gov/publications/nist-ai-600-1-artificial-intelligence-risk-management-framework-generative"]),
    # Phase 1.3.2: Training Process Security (AIML123-AIML132)
    Rule(rule_id="AIML123", name="gradient-manipulation", description="Gradient manipulation attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Gradient computation - validate to prevent manipulation attacks", explanation="Gradients can be manipulated to poison models", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "gradient", "security"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML124", name="learning-rate-manipulation", description="Learning rate manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dynamic learning rate without validation - manipulation risk", explanation="Learning rate changes should be validated", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "learning-rate", "security"}, references=["https://arxiv.org/abs/2006.08131"]),
    Rule(rule_id="AIML125", name="optimizer-state-poisoning", description="Optimizer state poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Optimizer state loading - verify integrity to prevent poisoning", explanation="Optimizer state can be poisoned between training sessions", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "optimizer", "security"}, references=["https://arxiv.org/abs/1804.00308"]),
    Rule(rule_id="AIML126", name="checkpoint-tampering-training", description="Checkpoint tampering during training", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Checkpoint saving without integrity checks - tampering risk", explanation="Training checkpoints should be integrity-protected", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "training", "checkpoint", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML127", name="early-stopping-bypass", description="Early stopping bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Early stopping without validation monitoring - bypass risk", explanation="Early stopping can be bypassed by validation set poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "early-stopping", "security"}, references=["https://arxiv.org/abs/2006.08131"]),
    Rule(rule_id="AIML128", name="validation-set-poisoning", description="Validation set poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Validation data from untrusted source - poisoning risk", explanation="Validation sets should be verified for integrity", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "validation", "security"}, references=["https://arxiv.org/abs/1804.00308"]),
    Rule(rule_id="AIML129", name="tensorboard-logging-injection", description="TensorBoard logging injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="TensorBoard logging - sanitize data to prevent injection", explanation="Logging data should be sanitized", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-117", owasp_mapping="ML05", tags={"ai", "ml", "training", "logging", "security"}, references=["https://www.tensorflow.org/tensorboard"]),
    Rule(rule_id="AIML130", name="experiment-tracking-manipulation", description="Experiment tracking manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Experiment tracking - validate metrics to prevent manipulation", explanation="Experiment metrics can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "tracking", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML131", name="distributed-training-node-compromise", description="Distributed training node compromise", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Distributed training - secure communication between nodes", explanation="Training nodes should authenticate and encrypt communication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-300", owasp_mapping="ML03", tags={"ai", "ml", "training", "distributed", "security"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML132", name="parameter-server-vulnerabilities", description="Parameter server vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Parameter server - implement authentication and encryption", explanation="Parameter servers need secure communication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-306", owasp_mapping="ML03", tags={"ai", "ml", "training", "parameter-server", "security"}, references=["https://arxiv.org/abs/1811.12470"]),
    # Phase 1.3.3: Fine-Tuning Risks (AIML133-AIML140)
    Rule(rule_id="AIML133", name="base-model-poisoning", description="Base model poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Fine-tuning from untrusted base model - poisoning risk", explanation="Base models should be verified before fine-tuning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "fine-tuning", "poisoning", "security"}, references=["https://arxiv.org/abs/2004.10908"]),
    Rule(rule_id="AIML134", name="fine-tuning-data-injection", description="Fine-tuning data injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Fine-tuning data - validate to prevent injection attacks", explanation="Fine-tuning data can inject backdoors", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "injection", "security"}, references=["https://arxiv.org/abs/2004.10908"]),
    Rule(rule_id="AIML135", name="catastrophic-forgetting-exploitation", description="Catastrophic forgetting exploitation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Fine-tuning without forgetting protection - exploitation risk", explanation="Fine-tuning can be exploited to remove security features", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "forgetting", "security"}, references=["https://arxiv.org/abs/1612.00796"]),
    Rule(rule_id="AIML136", name="peft-attacks", description="PEFT (Parameter Efficient Fine-Tuning) attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="PEFT without validation - parameter tampering risk", explanation="PEFT adapters can be exploited", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "peft", "security"}, references=["https://arxiv.org/abs/2106.09685"]),
    Rule(rule_id="AIML137", name="lora-poisoning", description="LoRA poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="LoRA adapter - verify source to prevent poisoning", explanation="LoRA adapters can contain backdoors", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "lora", "security"}, references=["https://arxiv.org/abs/2106.09685"]),
    Rule(rule_id="AIML138", name="adapter-injection", description="Adapter injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Adapter loading - validate to prevent malicious injection", explanation="Adapters can inject malicious behavior", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "adapter", "security"}, references=["https://arxiv.org/abs/1902.00751"]),
    Rule(rule_id="AIML139", name="prompt-tuning-manipulation", description="Prompt tuning manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Prompt tuning - validate prompts to prevent manipulation", explanation="Soft prompts can be manipulated to change behavior", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "fine-tuning", "prompt-tuning", "security"}, references=["https://arxiv.org/abs/2104.08691"]),
    Rule(rule_id="AIML140", name="instruction-fine-tuning-risks", description="Instruction fine-tuning risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Instruction fine-tuning - validate data to prevent jailbreaks", explanation="Instruction data can introduce jailbreak vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="LLM01", tags={"ai", "ml", "fine-tuning", "instruction", "security"}, references=["https://arxiv.org/abs/2109.01652"]),
    # Phase 1.4: Adversarial ML & Model Robustness (20 checks)
    # Phase 1.4.1: Adversarial Input Detection (AIML141-AIML150)
    Rule(rule_id="AIML141", name="missing-adversarial-defense", description="Missing input adversarial defense", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model inference without adversarial defense - attack vulnerability", explanation="Models should include adversarial input detection and defense", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "defense", "security"}, references=["https://arxiv.org/abs/1412.6572"]),
    Rule(rule_id="AIML142", name="no-fgsm-protection", description="No FGSM (Fast Gradient Sign Method) protection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model vulnerable to FGSM attacks - add adversarial training", explanation="Models should be hardened against FGSM attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "fgsm", "security"}, references=["https://arxiv.org/abs/1412.6572"]),
    Rule(rule_id="AIML143", name="pgd-vulnerability", description="PGD (Projected Gradient Descent) vulnerability", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model vulnerable to PGD attacks - implement robust training", explanation="PGD is a powerful adversarial attack that requires defense", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "pgd", "security"}, references=["https://arxiv.org/abs/1706.06083"]),
    Rule(rule_id="AIML144", name="cw-attack-surface", description="C&W (Carlini & Wagner) attack surface", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model vulnerable to C&W attacks - add defensive distillation", explanation="C&W attacks can bypass many defenses, requiring robust countermeasures", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "cw", "security"}, references=["https://arxiv.org/abs/1608.04644"]),
    Rule(rule_id="AIML145", name="deepfool-susceptibility", description="DeepFool susceptibility", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model vulnerable to DeepFool attacks - validate input perturbations", explanation="DeepFool finds minimal perturbations to fool models", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "deepfool", "security"}, references=["https://arxiv.org/abs/1511.04599"]),
    Rule(rule_id="AIML146", name="universal-adversarial-perturbations", description="Universal adversarial perturbations", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model vulnerable to universal perturbations - add input validation", explanation="Universal perturbations can fool models on any input", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "universal", "security"}, references=["https://arxiv.org/abs/1610.08401"]),
    Rule(rule_id="AIML147", name="black-box-attack-vulnerability", description="Black-box attack vulnerability", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model API exposes inference - black-box attack risk", explanation="Inference APIs enable black-box adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-200", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "black-box", "security"}, references=["https://arxiv.org/abs/1602.02697"]),
    Rule(rule_id="AIML148", name="transfer-attack-risks", description="Transfer attack risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model architecture similar to public models - transfer attack risk", explanation="Adversarial examples can transfer between models", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "transfer", "security"}, references=["https://arxiv.org/abs/1605.07277"]),
    Rule(rule_id="AIML149", name="physical-adversarial-examples", description="Physical adversarial examples", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Vision model without physical robustness - real-world attack risk", explanation="Physical adversarial examples work in the real world", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "physical", "security"}, references=["https://arxiv.org/abs/1607.02533"]),
    Rule(rule_id="AIML150", name="adversarial-patch-detection-missing", description="Adversarial patch detection missing", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Object detection without patch detection - adversarial sticker risk", explanation="Adversarial patches can fool object detection systems", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "adversarial", "patch", "security"}, references=["https://arxiv.org/abs/1712.09665"]),
    # Phase 1.4.2: Model Robustness (AIML151-AIML160)
    Rule(rule_id="AIML151", name="missing-adversarial-training", description="Missing adversarial training", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model trained without adversarial examples - weak robustness", explanation="Adversarial training improves model robustness", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "training", "security"}, references=["https://arxiv.org/abs/1706.06083"]),
    Rule(rule_id="AIML152", name="no-certified-defenses", description="No certified defenses", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model lacks certified robustness guarantees", explanation="Certified defenses provide provable robustness", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "certified", "security"}, references=["https://arxiv.org/abs/1805.12514"]),
    Rule(rule_id="AIML153", name="input-gradient-masking", description="Input gradient masking", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Model uses gradient masking - false sense of security", explanation="Gradient masking can be bypassed and provides weak defense", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "gradient-masking", "security"}, references=["https://arxiv.org/abs/1803.09868"]),
    Rule(rule_id="AIML154", name="defensive-distillation-gaps", description="Defensive distillation gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Defensive distillation incomplete - C&W vulnerability", explanation="Defensive distillation can be bypassed by advanced attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "distillation", "security"}, references=["https://arxiv.org/abs/1511.04508"]),
    Rule(rule_id="AIML155", name="ensemble-defenses-missing", description="Ensemble defenses missing", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Single model inference - consider ensemble for robustness", explanation="Ensemble methods improve adversarial robustness", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "ensemble", "security"}, references=["https://arxiv.org/abs/1705.07204"]),
    Rule(rule_id="AIML156", name="randomization-defense-gaps", description="Randomization defense gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Randomization defense weak - can be circumvented", explanation="Randomization alone provides limited adversarial protection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "randomization", "security"}, references=["https://arxiv.org/abs/1711.01991"]),
    Rule(rule_id="AIML157", name="input-transformation-missing", description="Input transformation missing", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="No input preprocessing defenses - add transformation layers", explanation="Input transformations can remove adversarial perturbations", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "transformation", "security"}, references=["https://arxiv.org/abs/1704.01155"]),
    Rule(rule_id="AIML158", name="detection-mechanism-missing", description="Detection mechanism missing", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="No adversarial example detector - add detection layer", explanation="Detection mechanisms can identify adversarial inputs", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "detection", "security"}, references=["https://arxiv.org/abs/1705.07263"]),
    Rule(rule_id="AIML159", name="rejection-option-missing", description="Rejection option missing", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model lacks confidence-based rejection - add uncertainty quantification", explanation="Rejection mechanisms can refuse low-confidence predictions", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "rejection", "security"}, references=["https://arxiv.org/abs/1802.04865"]),
    Rule(rule_id="AIML160", name="robustness-testing-absent", description="Robustness testing absent", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="No adversarial robustness testing - add evaluation suite", explanation="Models should be tested against adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-1059", owasp_mapping="ML04", tags={"ai", "ml", "robustness", "testing", "best-practice"}, references=["https://arxiv.org/abs/1902.06705"]),
    # Phase 2.1: Feature Engineering & Preprocessing (30 checks)
    # Phase 2.1.1: Data Preprocessing Security (AIML161-AIML175)
    Rule(rule_id="AIML161", name="missing-preprocessing-validation", description="Missing input validation in preprocessing", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Preprocessing without input validation - add validation checks", explanation="Input data should be validated before preprocessing to prevent attacks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "validation", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML162", name="normalization-bypass", description="Normalization bypass attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Normalization without bounds checking - bypass attack risk", explanation="Normalization should include bounds to prevent bypass attacks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "normalization", "security"}, references=["https://arxiv.org/abs/1811.11553"]),
    Rule(rule_id="AIML163", name="feature-scaling-manipulation", description="Feature scaling manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature scaling with user input - manipulation risk", explanation="Scaling parameters should be protected from user manipulation", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "scaling", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML164", name="missing-value-injection", description="Missing value injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Missing value imputation with dynamic strategy - injection risk", explanation="Imputation strategies should be validated to prevent injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "imputation", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML165", name="encoding-injection", description="Encoding injection (categorical features)", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Categorical encoding without validation - injection risk", explanation="Categorical encoders should validate input to prevent injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "encoding", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML166", name="feature-extraction-vulnerabilities", description="Feature extraction vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature extraction without validation - vulnerability risk", explanation="Feature extraction should validate inputs to prevent vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "extraction", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML167", name="dimensionality-reduction-poisoning", description="Dimensionality reduction poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dimensionality reduction without validation - poisoning risk", explanation="Dimensionality reduction should validate inputs to prevent poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "dimensionality", "security"}, references=["https://arxiv.org/abs/1804.00308"]),
    Rule(rule_id="AIML168", name="feature-selection-manipulation", description="Feature selection manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature selection with user input - manipulation risk", explanation="Feature selection criteria should be protected from manipulation", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "selection", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML169", name="missing-outlier-detection", description="Missing outlier detection", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Preprocessing without outlier detection - consider adding anomaly detection", explanation="Outlier detection can prevent poisoning attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "outliers", "best-practice"}, references=["https://arxiv.org/abs/1811.11553"]),
    Rule(rule_id="AIML170", name="data-leakage-preprocessing", description="Data leakage in preprocessing", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Data leakage - fitting preprocessing on test/validation data", explanation="Preprocessing should only fit on training data to prevent leakage", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-200", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "leakage", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML171", name="test-train-contamination", description="Test/train contamination", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Train/test split without random_state - reproducibility risk", explanation="Train/test splits should use random_state for reproducibility", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-330", owasp_mapping="ML03", tags={"ai", "ml", "preprocessing", "splitting", "best-practice"}, references=["https://scikit-learn.org/stable/modules/cross_validation.html"]),
    Rule(rule_id="AIML172", name="feature-store-injection", description="Feature store injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature store access without validation - injection risk", explanation="Feature store queries should be validated to prevent injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "injection", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML173", name="pipeline-versioning-gaps", description="Pipeline versioning gaps", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Pipeline saved without version metadata - tracking risk", explanation="Pipelines should include version metadata for tracking", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-778", owasp_mapping="ML03", tags={"ai", "ml", "pipeline", "versioning", "best-practice"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML174", name="preprocessing-state-tampering", description="Preprocessing state tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Preprocessing state loaded without integrity check - tampering risk", explanation="Preprocessing state should be integrity-checked when loaded", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "preprocessing", "tampering", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML175", name="transformation-order-vulnerabilities", description="Transformation order vulnerabilities", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Pipeline transformation order - document to prevent vulnerabilities", explanation="Transformation order should be documented for security review", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-693", owasp_mapping="ML03", tags={"ai", "ml", "pipeline", "order", "best-practice"}, references=["https://scikit-learn.org/stable/modules/compose.html"]),
    # Phase 2.1.2: Feature Store Security (AIML176-AIML190)
    Rule(rule_id="AIML176", name="feast-feature-store-injection", description="Feast feature store injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Feast feature store query with user input - injection risk", explanation="Feature store queries should validate inputs to prevent injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-89", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "feast", "injection"}, references=["https://docs.feast.dev/"]),
    Rule(rule_id="AIML177", name="missing-feature-validation", description="Missing feature validation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature retrieval without validation - integrity risk", explanation="Retrieved features should be validated for integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "validation"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML178", name="feature-drift-without-detection", description="Feature drift without detection", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Feature usage without drift detection - add monitoring", explanation="Feature drift should be monitored to maintain model quality", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML06", tags={"ai", "ml", "feature-store", "drift", "monitoring"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML179", name="feature-serving-vulnerabilities", description="Feature serving vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Feature serving without authentication - access control risk", explanation="Feature serving endpoints should require authentication", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "feature-store", "serving", "auth"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML180", name="offline-online-feature-skew", description="Offline/online feature skew", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Online feature serving - validate consistency with offline features", explanation="Online and offline features should be consistent to prevent skew", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "skew", "consistency"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML181", name="feature-metadata-tampering", description="Feature metadata tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature metadata update without integrity check - tampering risk", explanation="Feature metadata should be integrity-protected", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "feature-store", "metadata", "tampering"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML182", name="feature-lineage-missing", description="Feature lineage missing", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Feature creation without lineage tracking - add provenance metadata", explanation="Feature lineage enables security audits and debugging", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-778", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "lineage", "provenance"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML183", name="feature-access-control-gaps", description="Access control gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Feature access without authorization - add access control", explanation="Feature access should be role-based and authorized", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-862", owasp_mapping="A01", tags={"ai", "ml", "feature-store", "access-control", "authorization"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML184", name="feature-deletion-corruption", description="Feature deletion/corruption", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature deletion without backup - data loss risk", explanation="Feature deletion should include backup or soft delete", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-404", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "deletion", "backup"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML185", name="feature-version-control-weaknesses", description="Version control weaknesses", category=RuleCategory.CONVENTION, severity=RuleSeverity.LOW, message_template="Feature update without version control - tracking risk", explanation="Feature updates should be versioned for tracking and rollback", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-778", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "versioning"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML186", name="feature-freshness-attacks", description="Feature freshness attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature serving without freshness validation - stale data risk", explanation="Features should have TTL or timestamp validation", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-672", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "freshness", "ttl"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML187", name="batch-realtime-inconsistencies", description="Batch vs real-time inconsistencies", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Batch feature processing - validate consistency with real-time", explanation="Batch and real-time processing should produce consistent results", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "batch", "consistency"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML188", name="feature-engineering-code-injection", description="Feature engineering code injection", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Feature transformation with dynamic code - injection risk", explanation="Feature engineering should not use dynamic code execution", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="A03", tags={"ai", "ml", "feature-store", "injection", "code-execution"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML189", name="schema-evolution-attacks", description="Schema evolution attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Schema evolution without validation - compatibility risk", explanation="Schema changes should be validated for backward compatibility", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "schema", "evolution"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML190", name="feature-importance-manipulation", description="Feature importance manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature importance calculation with user input - manipulation risk", explanation="Feature importance should not be influenced by user input", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "feature-store", "importance", "manipulation"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    # Phase 2.2: Model Training Infrastructure (35 checks)
    # Phase 2.2.1: Distributed Training Security (AIML191-AIML205)
    Rule(rule_id="AIML191", name="parameter-server-vulnerabilities", description="Parameter server vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Parameter server - implement authentication and encryption", explanation="Parameter servers need secure communication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-306", owasp_mapping="ML03", tags={"ai", "ml", "training", "parameter-server", "security"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML192", name="gradient-aggregation-poisoning", description="Gradient aggregation poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Gradient aggregation - validate to prevent poisoning attacks", explanation="Gradient aggregation can be exploited for model poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "gradient", "poisoning"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML193", name="byzantine-worker-attacks", description="Byzantine worker attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Distributed training - add Byzantine worker detection", explanation="Byzantine workers can poison distributed training", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "byzantine", "distributed"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML194", name="all-reduce-manipulation", description="All-Reduce manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="All-Reduce operation - validate tensor values to prevent manipulation", explanation="All-Reduce operations can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "allreduce", "distributed"}, references=["https://pytorch.org/docs/stable/distributed.html"]),
    Rule(rule_id="AIML195", name="ring-all-reduce-injection", description="Ring-All-Reduce injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Ring-All-Reduce - implement secure communication to prevent injection", explanation="Ring-All-Reduce communication should be secured", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "ring-allreduce", "distributed"}, references=["https://arxiv.org/abs/1509.01916"]),
    Rule(rule_id="AIML196", name="horovod-security-gaps", description="Horovod security gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Horovod communication - enable TLS for secure distributed training", explanation="Horovod should use TLS for communication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-300", owasp_mapping="ML03", tags={"ai", "ml", "training", "horovod", "distributed"}, references=["https://horovod.readthedocs.io/"]),
    Rule(rule_id="AIML197", name="deepspeed-vulnerabilities", description="DeepSpeed vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="DeepSpeed initialization - validate configuration to prevent vulnerabilities", explanation="DeepSpeed configuration should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "training", "deepspeed", "distributed"}, references=["https://www.deepspeed.ai/"]),
    Rule(rule_id="AIML198", name="fsdp-risks", description="FSDP (Fully Sharded Data Parallel) risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="FSDP training - implement shard validation to prevent poisoning", explanation="FSDP shards should be validated for integrity", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "fsdp", "distributed"}, references=["https://pytorch.org/docs/stable/fsdp.html"]),
    Rule(rule_id="AIML199", name="zero-optimizer-state-attacks", description="ZeRO optimizer state attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ZeRO optimizer state - validate state integrity to prevent attacks", explanation="ZeRO optimizer state can be poisoned", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "zero", "optimizer"}, references=["https://www.deepspeed.ai/tutorials/zero/"]),
    Rule(rule_id="AIML200", name="model-parallel-partition-poisoning", description="Model parallel partition poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model parallel partitioning - validate partition integrity", explanation="Model partitions can be poisoned", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "model-parallel", "distributed"}, references=["https://pytorch.org/docs/stable/distributed.html"]),
    Rule(rule_id="AIML201", name="pipeline-parallel-injection", description="Pipeline parallel injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Pipeline parallel training - validate stage outputs to prevent injection", explanation="Pipeline stages can be exploited for injection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML03", tags={"ai", "ml", "training", "pipeline-parallel", "distributed"}, references=["https://pytorch.org/docs/stable/pipeline.html"]),
    Rule(rule_id="AIML202", name="tensor-parallel-tampering", description="Tensor parallel tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Tensor parallel training - validate tensor splits to prevent tampering", explanation="Tensor splits can be tampered with", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "tensor-parallel", "distributed"}, references=["https://pytorch.org/docs/stable/distributed.html"]),
    Rule(rule_id="AIML203", name="mixed-precision-training-risks", description="Mixed precision training risks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Mixed precision training - validate numerical stability to prevent attacks", explanation="Mixed precision can introduce numerical vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "training", "amp", "mixed-precision"}, references=["https://pytorch.org/docs/stable/amp.html"]),
    Rule(rule_id="AIML204", name="communication-backend-vulnerabilities", description="Communication backend vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Communication backend - use secure backend (e.g., NCCL) for distributed training", explanation="Communication backends should be secure", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-300", owasp_mapping="ML03", tags={"ai", "ml", "training", "backend", "distributed"}, references=["https://pytorch.org/docs/stable/distributed.html"]),
    Rule(rule_id="AIML205", name="collective-operation-manipulation", description="Collective operation manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Collective operation - validate tensor data to prevent manipulation", explanation="Collective operations can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "training", "collective", "distributed"}, references=["https://pytorch.org/docs/stable/distributed.html"]),
    # Phase 2.2.2: GPU & Accelerator Security (AIML206-AIML215)
    Rule(rule_id="AIML206", name="gpu-memory-leakage", description="GPU memory leakage", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="GPU memory allocation - ensure proper cleanup to prevent memory leaks", explanation="GPU memory should be properly managed and released", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-401", owasp_mapping="ML03", tags={"ai", "ml", "gpu", "memory", "leak"}, references=["https://pytorch.org/docs/stable/notes/cuda.html"]),
    Rule(rule_id="AIML207", name="cuda-kernel-injection", description="CUDA kernel injection", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Custom CUDA kernel - validate source to prevent code injection", explanation="Custom CUDA kernels should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-94", owasp_mapping="ML03", tags={"ai", "ml", "cuda", "kernel", "injection"}, references=["https://docs.nvidia.com/cuda/cuda-c-programming-guide/"]),
    Rule(rule_id="AIML208", name="rocm-vulnerabilities", description="ROCm vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ROCm usage - validate kernel code and memory management", explanation="ROCm operations should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "rocm", "amd", "gpu"}, references=["https://rocm.docs.amd.com/"]),
    Rule(rule_id="AIML209", name="tpu-security-gaps", description="TPU security gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="TPU usage - validate computation and memory management", explanation="TPU operations should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "tpu", "xla", "accelerator"}, references=["https://cloud.google.com/tpu/docs"]),
    Rule(rule_id="AIML210", name="npu-ipu-risks", description="NPU/IPU risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="NPU/IPU usage - validate accelerator configuration and operations", explanation="NPU/IPU operations should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML03", tags={"ai", "ml", "npu", "ipu", "accelerator"}, references=["https://www.graphcore.ai/products/ipu"]),
    Rule(rule_id="AIML211", name="multi-gpu-synchronization-attacks", description="Multi-GPU synchronization attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Multi-GPU training - validate synchronization to prevent attacks", explanation="Multi-GPU synchronization can be exploited", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "gpu", "multi-gpu", "synchronization"}, references=["https://pytorch.org/docs/stable/nn.html#dataparallel"]),
    Rule(rule_id="AIML212", name="device-placement-manipulation", description="Device placement manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Device placement with user input - manipulation risk", explanation="Device placement should not be user-controllable", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "gpu", "device", "placement"}, references=["https://pytorch.org/docs/stable/tensor_attributes.html"]),
    Rule(rule_id="AIML213", name="cuda-graph-poisoning", description="CUDA graph poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="CUDA graph - validate graph structure to prevent poisoning", explanation="CUDA graphs can be poisoned", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cuda", "graph", "poisoning"}, references=["https://pytorch.org/docs/stable/notes/cuda.html#cuda-graphs"]),
    Rule(rule_id="AIML214", name="kernel-launch-parameter-tampering", description="Kernel launch parameter tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Kernel launch - validate parameters to prevent tampering", explanation="Kernel launch parameters can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cuda", "kernel", "parameters"}, references=["https://docs.nvidia.com/cuda/cuda-c-programming-guide/"]),
    Rule(rule_id="AIML215", name="gpu-memory-exhaustion-attacks", description="GPU memory exhaustion attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="GPU tensor allocation - validate size to prevent memory exhaustion", explanation="Large GPU allocations can cause DoS", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML03", tags={"ai", "ml", "gpu", "memory", "dos"}, references=["https://pytorch.org/docs/stable/notes/cuda.html"]),
    # Phase 2.2.3: Experiment Tracking Security (AIML216-AIML225)
    Rule(rule_id="AIML216", name="mlflow-injection-attacks", description="MLflow injection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="MLflow logging with user input - injection risk, validate data", explanation="MLflow can be exploited via injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="ML03", tags={"ai", "ml", "mlflow", "tracking", "injection"}, references=["https://mlflow.org/docs/latest/security.html"]),
    Rule(rule_id="AIML217", name="wandb-credential-leakage", description="Weights & Biases credential leakage", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Weights & Biases API key hardcoded - use environment variables", explanation="API keys should not be hardcoded", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-798", owasp_mapping="A07", tags={"ai", "ml", "wandb", "credentials", "hardcoded"}, references=["https://docs.wandb.ai/guides/track/environment-variables"]),
    Rule(rule_id="AIML218", name="cometml-experiment-tampering", description="Comet.ml experiment tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Comet.ml experiment data - validate to prevent tampering", explanation="Experiment data should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cometml", "tracking", "tampering"}, references=["https://www.comet.com/docs/v2/"]),
    Rule(rule_id="AIML219", name="tensorboard-rce", description="TensorBoard remote code execution", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="TensorBoard logging with user input - RCE risk, sanitize data", explanation="TensorBoard can execute arbitrary code via malicious data", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="ML05", tags={"ai", "ml", "tensorboard", "rce", "injection"}, references=["https://www.tensorflow.org/tensorboard/security"]),
    Rule(rule_id="AIML220", name="neptuneai-model-manipulation", description="Neptune.ai model manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Neptune.ai model logging - validate data to prevent manipulation", explanation="Neptune.ai artifacts should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "neptune", "tracking", "manipulation"}, references=["https://docs.neptune.ai/"]),
    Rule(rule_id="AIML221", name="experiment-metadata-injection", description="Experiment metadata injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Experiment metadata with user input - injection risk, sanitize data", explanation="Experiment metadata should be sanitized", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="ML03", tags={"ai", "ml", "metadata", "tracking", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML222", name="metric-tampering", description="Metric tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Metric logging - validate values to prevent tampering", explanation="Metrics should be validated for integrity", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "metrics", "tracking", "tampering"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML223", name="artifact-poisoning", description="Artifact poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Artifact upload - validate integrity with checksums to prevent poisoning", explanation="Artifacts should have integrity checks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "artifacts", "tracking", "poisoning"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML224", name="run-comparison-manipulation", description="Run comparison manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Run comparison - validate run IDs to prevent manipulation", explanation="Run comparisons should validate run identities", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "comparison", "tracking", "manipulation"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML225", name="hyperparameter-logging-risks", description="Hyperparameter logging risks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Hyperparameter logging - avoid logging sensitive data (keys, passwords)", explanation="Hyperparameters should not contain sensitive data", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-200", owasp_mapping="A02", tags={"ai", "ml", "hyperparameters", "tracking", "leakage"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    # Phase 2.3: Model Deployment & Serving (35 checks)
    # Phase 2.3.1: Model Serving Vulnerabilities (AIML226-AIML240)
    Rule(rule_id="AIML226", name="torchserve-vulnerabilities", description="TorchServe vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="TorchServe deployment - enable authentication and input validation", explanation="TorchServe endpoints should be properly secured", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "serving", "torchserve", "security"}, references=["https://pytorch.org/serve/"]),
    Rule(rule_id="AIML227", name="tensorflow-serving-injection", description="TensorFlow Serving injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="TensorFlow Serving - validate inputs to prevent injection attacks", explanation="TensorFlow Serving should validate all inputs", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML09", tags={"ai", "ml", "serving", "tensorflow", "injection"}, references=["https://www.tensorflow.org/tfx/guide/serving"]),
    Rule(rule_id="AIML228", name="onnx-runtime-risks", description="ONNX Runtime risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ONNX Runtime - validate model integrity before loading", explanation="ONNX models should be integrity-checked", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "serving", "onnx", "security"}, references=["https://onnxruntime.ai/"]),
    Rule(rule_id="AIML229", name="triton-inference-server-gaps", description="Triton Inference Server gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Triton Inference Server - enable access controls and rate limiting", explanation="Triton should have proper access controls", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-862", owasp_mapping="A01", tags={"ai", "ml", "serving", "triton", "security"}, references=["https://github.com/triton-inference-server/server"]),
    Rule(rule_id="AIML230", name="bentoml-security-issues", description="BentoML security issues", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="BentoML deployment - implement authentication and input validation", explanation="BentoML APIs should be secured", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "serving", "bentoml", "security"}, references=["https://docs.bentoml.org/"]),
    Rule(rule_id="AIML231", name="ray-serve-vulnerabilities", description="Ray Serve vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Ray Serve deployment - validate inputs and enable authentication", explanation="Ray Serve endpoints should be secured", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "serving", "ray", "security"}, references=["https://docs.ray.io/en/latest/serve/"]),
    Rule(rule_id="AIML232", name="seldon-core-risks", description="Seldon Core risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Seldon Core deployment - implement proper security policies", explanation="Seldon Core deployments should have security policies", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-862", owasp_mapping="A01", tags={"ai", "ml", "serving", "seldon", "security"}, references=["https://docs.seldon.io/projects/seldon-core/"]),
    Rule(rule_id="AIML233", name="kserve-weaknesses", description="KServe weaknesses", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="KServe deployment - enable TLS and authentication", explanation="KServe should use TLS and authentication", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-319", owasp_mapping="A02", tags={"ai", "ml", "serving", "kserve", "security"}, references=["https://kserve.github.io/website/"]),
    Rule(rule_id="AIML234", name="model-batching-attacks", description="Model batching attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model batching - validate batch size to prevent DoS attacks", explanation="Batch size should be limited to prevent resource exhaustion", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "serving", "batching", "dos"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML235", name="dynamic-batching-poisoning", description="Dynamic batching poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dynamic batching - validate inputs to prevent batch poisoning", explanation="Dynamic batching can be exploited for poisoning attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "serving", "batching", "poisoning"}, references=["https://arxiv.org/abs/2004.10941"]),
    Rule(rule_id="AIML236", name="model-versioning-bypass", description="Model versioning bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model serving - pin version to prevent unauthorized updates", explanation="Model versions should be explicitly specified", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "serving", "versioning", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML237", name="ab-testing-manipulation", description="A/B testing manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="A/B testing - validate traffic split to prevent manipulation", explanation="A/B testing traffic should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "serving", "ab-testing", "manipulation"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML238", name="canary-deployment-risks", description="Canary deployment risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Canary deployment - validate rollout percentages and monitoring", explanation="Canary deployments should have proper validation and monitoring", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "serving", "canary", "deployment"}, references=["https://martinfowler.com/bliki/CanaryRelease.html"]),
    Rule(rule_id="AIML239", name="blue-green-deployment-gaps", description="Blue-green deployment gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Blue-green deployment - validate switchover to prevent issues", explanation="Blue-green deployments should validate before switching", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "serving", "blue-green", "deployment"}, references=["https://martinfowler.com/bliki/BlueGreenDeployment.html"]),
    Rule(rule_id="AIML240", name="shadow-deployment-leakage", description="Shadow deployment leakage", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Shadow deployment - ensure no data leakage from shadow traffic", explanation="Shadow deployments should not leak data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-200", owasp_mapping="A02", tags={"ai", "ml", "serving", "shadow", "leakage"}, references=["https://netflixtechblog.com/a-day-in-the-life-of-a-netflix-engineer-automating-security-f3f1f0117e4"]),
    # Phase 2.3.2: API & Endpoint Security (AIML241-AIML252)
    Rule(rule_id="AIML241", name="missing-inference-authentication", description="Missing authentication on inference API", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Inference API without authentication - add authentication layer", explanation="Inference endpoints must require authentication", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "api", "authentication", "security"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML242", name="model-endpoint-enumeration", description="Model endpoint enumeration", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model endpoint exposed - implement access controls to prevent enumeration", explanation="Model endpoints should not be easily enumerable", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-200", owasp_mapping="A01", tags={"ai", "ml", "api", "enumeration", "security"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML243", name="batch-inference-injection", description="Batch inference injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Batch inference - validate all inputs to prevent injection", explanation="Batch inference should validate inputs individually", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML09", tags={"ai", "ml", "api", "batch", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML244", name="streaming-inference-attacks", description="Streaming inference attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Streaming inference - validate stream data to prevent attacks", explanation="Streaming inference should validate all stream data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-20", owasp_mapping="ML09", tags={"ai", "ml", "api", "streaming", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML245", name="model-cache-poisoning", description="Model cache poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Model caching - validate cache integrity to prevent poisoning", explanation="Model cache should be integrity-protected", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML05", tags={"ai", "ml", "api", "cache", "poisoning"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML246", name="prediction-logging-pii-risks", description="Prediction logging risks (PII)", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Prediction logging - avoid logging PII data", explanation="Predictions should not log personally identifiable information", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-359", owasp_mapping="A02", tags={"ai", "ml", "api", "logging", "pii"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML247", name="model-warmup-vulnerabilities", description="Model warm-up vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Model warm-up - validate warm-up requests to prevent abuse", explanation="Model warm-up should not expose vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "api", "warmup", "security"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML248", name="health-check-information-disclosure", description="Health check information disclosure", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Health check endpoint - limit information disclosure", explanation="Health checks should not reveal sensitive information", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-200", owasp_mapping="A01", tags={"ai", "ml", "api", "health", "disclosure"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML249", name="metrics-endpoint-exposure", description="Metrics endpoint exposure", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Metrics endpoint - restrict access to prevent information leakage", explanation="Metrics endpoints should be access-controlled", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-200", owasp_mapping="A05", tags={"ai", "ml", "api", "metrics", "exposure"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML250", name="model-metadata-leakage", description="Model metadata leakage", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model metadata exposed - limit information disclosure", explanation="Model metadata should not be publicly accessible", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-200", owasp_mapping="ML09", tags={"ai", "ml", "api", "metadata", "leakage"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML251", name="feature-flag-manipulation", description="Feature flag manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature flags - protect from user manipulation", explanation="Feature flags should not be user-controllable", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-807", owasp_mapping="A01", tags={"ai", "ml", "api", "feature-flags", "manipulation"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML252", name="circuit-breaker-bypass", description="Circuit breaker bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Circuit breaker - validate implementation to prevent bypass", explanation="Circuit breakers should not be bypassable", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML09", tags={"ai", "ml", "api", "circuit-breaker", "bypass"}, references=["https://martinfowler.com/bliki/CircuitBreaker.html"]),
    # Phase 2.3.3: Edge & Mobile Deployment (AIML253-AIML260)
    Rule(rule_id="AIML253", name="tflite-model-tampering", description="TFLite model tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="TFLite model - verify integrity before mobile deployment", explanation="TFLite models should be integrity-protected", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "edge", "tflite", "tampering"}, references=["https://www.tensorflow.org/lite"]),
    Rule(rule_id="AIML254", name="coreml-injection", description="Core ML injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Core ML model - validate model before iOS deployment", explanation="Core ML models should be validated", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "edge", "coreml", "injection"}, references=["https://developer.apple.com/documentation/coreml"]),
    Rule(rule_id="AIML255", name="onnx-mobile-risks", description="ONNX mobile risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ONNX mobile deployment - verify model integrity", explanation="ONNX models on mobile should be integrity-checked", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML05", tags={"ai", "ml", "edge", "onnx", "mobile"}, references=["https://onnx.ai/"]),
    Rule(rule_id="AIML256", name="quantized-model-vulnerabilities", description="Quantized model vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model quantization - validate to prevent accuracy degradation attacks", explanation="Quantized models can be exploited through precision attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML04", tags={"ai", "ml", "edge", "quantization", "security"}, references=["https://arxiv.org/abs/2004.10708"]),
    Rule(rule_id="AIML257", name="model-pruning-attacks", description="Model pruning attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Model pruning - validate to prevent backdoor persistence", explanation="Pruned models can retain hidden backdoors", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-912", owasp_mapping="ML03", tags={"ai", "ml", "edge", "pruning", "backdoor"}, references=["https://arxiv.org/abs/2003.03888"]),
    Rule(rule_id="AIML258", name="knowledge-distillation-risks", description="Knowledge distillation risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Knowledge distillation - validate student model for backdoors", explanation="Distilled models can inherit vulnerabilities from teacher", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-912", owasp_mapping="ML03", tags={"ai", "ml", "edge", "distillation", "backdoor"}, references=["https://arxiv.org/abs/1511.04508"]),
    Rule(rule_id="AIML259", name="on-device-training-weaknesses", description="On-device training weaknesses", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="On-device training - validate training data to prevent poisoning", explanation="On-device training can be poisoned by malicious data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "edge", "training", "poisoning"}, references=["https://arxiv.org/abs/1811.12470"]),
    Rule(rule_id="AIML260", name="federated-learning-gaps", description="Federated learning gaps", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Federated learning - implement Byzantine-robust aggregation", explanation="Federated learning vulnerable to Byzantine attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "edge", "federated", "byzantine"}, references=["https://arxiv.org/abs/1811.12470"]),
    # Phase 2.4: Model Monitoring & Observability (20 checks)
    # Phase 2.4.1: Drift Detection Security (AIML261-AIML270)
    Rule(rule_id="AIML261", name="data-drift-detection-bypass", description="Data drift detection bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Drift detection - implement comprehensive monitoring to prevent bypass", explanation="Drift detection should monitor all relevant features", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "drift", "bypass"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML262", name="concept-drift-manipulation", description="Concept drift manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Concept drift monitoring - validate label distributions to prevent manipulation", explanation="Concept drift can be manipulated through label poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "drift", "manipulation"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML263", name="model-performance-degradation-hiding", description="Model performance degradation hiding", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Performance monitoring - implement tamper-proof metrics to prevent hiding", explanation="Performance metrics should be tamper-resistant", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "performance", "tampering"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML264", name="prediction-distribution-poisoning", description="Prediction distribution poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Prediction monitoring - validate distribution to prevent poisoning", explanation="Prediction distributions can be poisoned", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "predictions", "poisoning"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML265", name="monitoring-pipeline-injection", description="Monitoring pipeline injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Monitoring pipeline - validate data sources to prevent injection", explanation="Monitoring pipelines should validate all data sources", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-94", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "pipeline", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML266", name="alert-threshold-manipulation", description="Alert threshold manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Alert thresholds - protect from user manipulation", explanation="Alert thresholds should not be user-controllable", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-807", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "alerts", "manipulation"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML267", name="logging-framework-vulnerabilities", description="Logging framework vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Logging framework - validate logging data to prevent injection", explanation="Logging frameworks should validate all data", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-117", owasp_mapping="A09", tags={"ai", "ml", "monitoring", "logging", "injection"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML268", name="missing-drift-detection", description="Missing drift detection", category=RuleCategory.CONVENTION, severity=RuleSeverity.MEDIUM, message_template="Production model - implement drift detection for monitoring", explanation="Production models should have drift detection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "drift", "best-practice"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML269", name="statistical-test-manipulation", description="Statistical test manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Statistical tests - validate test parameters to prevent manipulation", explanation="Statistical test parameters should be protected", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "statistics", "manipulation"}, references=["https://arxiv.org/abs/2004.03045"]),
    Rule(rule_id="AIML270", name="ground-truth-poisoning", description="Ground truth poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Ground truth collection - validate to prevent poisoning attacks", explanation="Ground truth data should be validated for integrity", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "monitoring", "ground-truth", "poisoning"}, references=["https://arxiv.org/abs/1804.00308"]),
    # Phase 2.4.2: Explainability & Interpretability (AIML271-AIML280)
    Rule(rule_id="AIML271", name="shap-value-manipulation", description="SHAP value manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="SHAP explanations - validate to prevent manipulation", explanation="SHAP values can be manipulated to hide biases", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "shap", "manipulation"}, references=["https://github.com/slundberg/shap"]),
    Rule(rule_id="AIML272", name="lime-explanation-poisoning", description="LIME explanation poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="LIME explanations - validate to prevent poisoning", explanation="LIME explanations can be poisoned", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "lime", "poisoning"}, references=["https://github.com/marcotcr/lime"]),
    Rule(rule_id="AIML273", name="feature-importance-injection", description="Feature importance injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Feature importance - validate calculations to prevent injection", explanation="Feature importance can be manipulated", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "importance", "injection"}, references=["https://scikit-learn.org/stable/modules/permutation_importance.html"]),
    Rule(rule_id="AIML274", name="saliency-map-tampering", description="Saliency map tampering", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Saliency maps - validate to prevent tampering", explanation="Saliency maps can be tampered to hide attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "saliency", "tampering"}, references=["https://arxiv.org/abs/1312.6034"]),
    Rule(rule_id="AIML275", name="attention-weight-manipulation", description="Attention weight manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Attention weights - validate to prevent manipulation", explanation="Attention weights can be manipulated to hide biases", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "attention", "manipulation"}, references=["https://arxiv.org/abs/1706.03762"]),
    Rule(rule_id="AIML276", name="counterfactual-explanation-attacks", description="Counterfactual explanation attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Counterfactual explanations - validate to prevent adversarial attacks", explanation="Counterfactual explanations can reveal model vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-200", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "counterfactual", "attacks"}, references=["https://arxiv.org/abs/1711.00399"]),
    Rule(rule_id="AIML277", name="model-card-injection", description="Model card injection", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Model card - sanitize user input to prevent injection", explanation="Model cards should sanitize all user input", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-79", owasp_mapping="A03", tags={"ai", "ml", "explainability", "model-card", "injection"}, references=["https://arxiv.org/abs/1810.03993"]),
    Rule(rule_id="AIML278", name="explanation-dashboard-vulnerabilities", description="Explanation dashboard vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Explanation dashboard - implement authentication and input validation", explanation="Explanation dashboards should be secured", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-306", owasp_mapping="A01", tags={"ai", "ml", "explainability", "dashboard", "security"}, references=["https://owasp.org/www-project-top-ten/"]),
    Rule(rule_id="AIML279", name="fairness-metric-manipulation", description="Fairness metric manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Fairness metrics - protect from manipulation to hide biases", explanation="Fairness metrics should be tamper-resistant", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "fairness", "manipulation"}, references=["https://arxiv.org/abs/1810.01943"]),
    Rule(rule_id="AIML280", name="bias-detection-bypass", description="Bias detection bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Bias detection - implement comprehensive checks to prevent bypass", explanation="Bias detection should be comprehensive and tamper-proof", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML06", tags={"ai", "ml", "explainability", "bias", "bypass"}, references=["https://arxiv.org/abs/1810.01943"]),
    # Phase 3: Specialized AI/ML Frameworks (100 checks)
    # Phase 3.1: Computer Vision Security (35 checks)
    # Phase 3.1.1: Image Processing Vulnerabilities (AIML281-AIML295)
    Rule(rule_id="AIML281", name="opencv-injection-attacks", description="OpenCV injection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="OpenCV injection - validate file paths and inputs to prevent attacks", explanation="OpenCV operations should validate all inputs for security", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML09", tags={"ai", "ml", "cv", "opencv", "injection"}, references=["https://docs.opencv.org/"]),
    Rule(rule_id="AIML282", name="pillow-buffer-overflows", description="PIL/Pillow buffer overflows", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="PIL/Pillow image loading - validate image format and size to prevent buffer overflows", explanation="Image loading should validate formats and dimensions", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-120", owasp_mapping="ML09", tags={"ai", "ml", "cv", "pillow", "buffer-overflow"}, references=["https://pillow.readthedocs.io/"]),
    Rule(rule_id="AIML283", name="image-augmentation-poisoning", description="Image augmentation poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Image augmentation - validate augmentation parameters to prevent poisoning", explanation="Augmentation should use validated and bounded parameters", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "augmentation", "poisoning"}, references=["https://arxiv.org/abs/1804.00308"]),
    Rule(rule_id="AIML284", name="exif-metadata-injection", description="EXIF metadata injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="EXIF metadata - sanitize metadata to prevent injection attacks", explanation="EXIF data should be sanitized before use", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML09", tags={"ai", "ml", "cv", "exif", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML285", name="adversarial-patch-attacks", description="Adversarial patch attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Vision model - implement defenses against adversarial patch attacks", explanation="Vision models should detect adversarial patches", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "adversarial", "patch"}, references=["https://arxiv.org/abs/1712.09665"]),
    Rule(rule_id="AIML286", name="texture-synthesis-manipulation", description="Texture synthesis manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Texture synthesis - validate generated textures to prevent manipulation", explanation="Synthesized textures should be validated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "texture", "manipulation"}, references=["https://arxiv.org/abs/1505.07376"]),
    Rule(rule_id="AIML287", name="style-transfer-poisoning", description="Style transfer poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Style transfer - validate style inputs to prevent poisoning", explanation="Style transfer should validate style images", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "style-transfer", "poisoning"}, references=["https://arxiv.org/abs/1508.06576"]),
    Rule(rule_id="AIML288", name="super-resolution-attacks", description="Super-resolution attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Super-resolution - validate inputs to prevent adversarial attacks", explanation="Super-resolution models can be exploited via adversarial inputs", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "super-resolution", "adversarial"}, references=["https://arxiv.org/abs/1501.00092"]),
    Rule(rule_id="AIML289", name="image-segmentation-manipulation", description="Image segmentation manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Segmentation model - implement defenses against manipulation attacks", explanation="Segmentation models should detect manipulated inputs", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "segmentation", "manipulation"}, references=["https://arxiv.org/abs/1704.06857"]),
    Rule(rule_id="AIML290", name="object-detection-bypass", description="Object detection bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Object detection - implement robustness against bypass attacks", explanation="Object detection should be robust to adversarial examples", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "object-detection", "bypass"}, references=["https://arxiv.org/abs/1412.6572"]),
    Rule(rule_id="AIML291", name="facial-recognition-spoofing", description="Facial recognition spoofing", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Facial recognition - implement liveness detection to prevent spoofing", explanation="Facial recognition should include anti-spoofing measures", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-287", owasp_mapping="A07", tags={"ai", "ml", "cv", "facial-recognition", "spoofing"}, references=["https://arxiv.org/abs/1901.08897"]),
    Rule(rule_id="AIML292", name="ocr-injection-attacks", description="OCR injection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="OCR processing - sanitize output to prevent injection via manipulated images", explanation="OCR output should be sanitized before use in commands or queries", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML09", tags={"ai", "ml", "cv", "ocr", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML293", name="image-captioning-poisoning", description="Image captioning poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Image captioning - validate captions to prevent poisoning attacks", explanation="Captioning models should validate generated text", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "captioning", "poisoning"}, references=["https://arxiv.org/abs/1502.03044"]),
    Rule(rule_id="AIML294", name="visual-question-answering-attacks", description="Visual question answering attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="VQA model - validate questions and answers to prevent attacks", explanation="VQA models should validate both questions and generated answers", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML09", tags={"ai", "ml", "cv", "vqa", "attacks"}, references=["https://arxiv.org/abs/1505.00468"]),
    Rule(rule_id="AIML295", name="video-frame-injection", description="Video frame injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Video processing - validate frames to prevent injection attacks", explanation="Video frames should be validated for integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML09", tags={"ai", "ml", "cv", "video", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    # Phase 3.1.2: Vision Transformers (AIML296-AIML305)
    Rule(rule_id="AIML296", name="patch-embedding-manipulation", description="Patch embedding manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Vision Transformer patch embedding - validate patches to prevent manipulation", explanation="ViT patch embeddings can be manipulated to fool the model", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "vit", "patch-embedding"}, references=["https://arxiv.org/abs/2010.11929"]),
    Rule(rule_id="AIML297", name="position-encoding-injection", description="Position encoding injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Vision Transformer position encoding - validate to prevent injection", explanation="Position encodings can be injected to manipulate model behavior", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "vit", "position-encoding"}, references=["https://arxiv.org/abs/2010.11929"]),
    Rule(rule_id="AIML298", name="attention-mechanism-attacks", description="Attention mechanism attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Vision Transformer attention - implement defenses against attention manipulation", explanation="Attention mechanisms can be exploited for adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "vit", "attention"}, references=["https://arxiv.org/abs/2010.11929"]),
    Rule(rule_id="AIML299", name="vision-language-model-risks", description="Vision-language model risks (CLIP)", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="CLIP model - validate both image and text inputs to prevent cross-modal attacks", explanation="Vision-language models vulnerable to cross-modal adversarial examples", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "clip", "multimodal"}, references=["https://arxiv.org/abs/2103.00020"]),
    Rule(rule_id="AIML300", name="diffusion-model-injection", description="Diffusion model injection (Stable Diffusion)", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Stable Diffusion - sanitize prompts and validate generated images", explanation="Diffusion models can generate harmful content via prompt injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML01", tags={"ai", "ml", "cv", "diffusion", "stable-diffusion"}, references=["https://arxiv.org/abs/2112.10752"]),
    Rule(rule_id="AIML301", name="text-to-image-prompt-injection", description="Text-to-image prompt injection", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="Text-to-image generation - sanitize prompts to prevent harmful content", explanation="Text-to-image models vulnerable to prompt injection attacks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML01", tags={"ai", "ml", "cv", "text-to-image", "prompt-injection"}, references=["https://arxiv.org/abs/2112.10752"]),
    Rule(rule_id="AIML302", name="image-to-image-manipulation", description="Image-to-image manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Image-to-image translation - validate inputs to prevent malicious manipulation", explanation="Image translation models can be exploited for deepfakes", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "image-to-image", "manipulation"}, references=["https://arxiv.org/abs/1703.10593"]),
    Rule(rule_id="AIML303", name="inpainting-attacks", description="Inpainting attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Image inpainting - validate masked regions to prevent attacks", explanation="Inpainting can be exploited to insert malicious content", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "inpainting", "attacks"}, references=["https://arxiv.org/abs/1801.07892"]),
    Rule(rule_id="AIML304", name="outpainting-vulnerabilities", description="Outpainting vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Image outpainting - validate generated regions for consistency", explanation="Outpainting can generate inconsistent or harmful content", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "cv", "outpainting", "vulnerabilities"}, references=["https://arxiv.org/abs/1901.07518"]),
    Rule(rule_id="AIML305", name="multimodal-fusion-risks", description="Multimodal fusion risks", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Multimodal fusion - validate cross-modal interactions to prevent attacks", explanation="Multimodal models vulnerable to cross-modal adversarial examples", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "multimodal", "fusion"}, references=["https://arxiv.org/abs/2103.00020"]),
    # Phase 3.1.3: CNN & Architecture Security (AIML306-AIML315)
    Rule(rule_id="AIML306", name="resnet-skip-connection-attacks", description="ResNet skip connection attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ResNet architecture - validate skip connections to prevent gradient manipulation", explanation="ResNet skip connections can be exploited for gradient-based attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "resnet", "skip-connection"}, references=["https://arxiv.org/abs/1512.03385"]),
    Rule(rule_id="AIML307", name="densenet-feature-concatenation", description="DenseNet feature concatenation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="DenseNet architecture - validate feature concatenation for integrity", explanation="DenseNet feature concatenation vulnerable to manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "densenet", "concatenation"}, references=["https://arxiv.org/abs/1608.06993"]),
    Rule(rule_id="AIML308", name="efficientnet-scaling-manipulation", description="EfficientNet scaling manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="EfficientNet - validate compound scaling parameters to prevent manipulation", explanation="EfficientNet scaling can be exploited for resource exhaustion", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "cv", "efficientnet", "scaling"}, references=["https://arxiv.org/abs/1905.11946"]),
    Rule(rule_id="AIML309", name="mobilenet-depthwise-convolution-risks", description="MobileNet depthwise convolution risks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="MobileNet - validate depthwise convolutions for numerical stability", explanation="Depthwise convolutions can introduce numerical vulnerabilities", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML04", tags={"ai", "ml", "cv", "mobilenet", "depthwise"}, references=["https://arxiv.org/abs/1704.04861"]),
    Rule(rule_id="AIML310", name="squeezenet-fire-module-injection", description="SqueezeNet fire module injection", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="SqueezeNet - validate fire module parameters", explanation="Fire modules can be exploited through parameter manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "squeezenet", "fire-module"}, references=["https://arxiv.org/abs/1602.07360"]),
    Rule(rule_id="AIML311", name="neural-architecture-search-poisoning", description="Neural architecture search poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="NAS - validate search space and architecture selection to prevent poisoning", explanation="Neural architecture search can be poisoned to select vulnerable architectures", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "nas", "poisoning"}, references=["https://arxiv.org/abs/1808.05377"]),
    Rule(rule_id="AIML312", name="activation-function-vulnerabilities", description="Activation function vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Custom activation functions - validate for numerical stability and gradient flow", explanation="Custom activations can introduce numerical vulnerabilities", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "cv", "activation", "vulnerability"}, references=["https://arxiv.org/abs/1710.05941"]),
    Rule(rule_id="AIML313", name="pooling-layer-manipulation", description="Pooling layer manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Pooling layers - validate pooling parameters to prevent manipulation", explanation="Pooling operations can be exploited for adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "cv", "pooling", "manipulation"}, references=["https://arxiv.org/abs/1412.6806"]),
    Rule(rule_id="AIML314", name="dropout-bypass-techniques", description="Dropout bypass techniques", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dropout layers - ensure proper training/inference mode to prevent bypass", explanation="Dropout can be bypassed by manipulating training/inference mode", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-754", owasp_mapping="ML03", tags={"ai", "ml", "cv", "dropout", "bypass"}, references=["https://arxiv.org/abs/1207.0580"]),
    Rule(rule_id="AIML315", name="batch-normalization-attacks", description="Batch normalization attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Batch normalization - validate statistics to prevent poisoning attacks", explanation="Batch norm statistics can be poisoned during training", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "cv", "batchnorm", "poisoning"}, references=["https://arxiv.org/abs/1502.03167"]),
    # Phase 3.2: Natural Language Processing Security (35 checks - AIML316-AIML350)
    # Phase 3.2.1: Text Processing Security (AIML316-AIML330)
    Rule(rule_id="AIML316", name="tokenization-injection", description="Tokenization injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Tokenization - validate input text to prevent injection attacks", explanation="Tokenization should validate inputs to prevent malicious token injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML01", tags={"ai", "ml", "nlp", "tokenization", "injection"}, references=["https://owasp.org/www-project-machine-learning-security-top-10/"]),
    Rule(rule_id="AIML317", name="subword-tokenization-bypass", description="Subword tokenization bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Subword tokenization - sanitize inputs to prevent bypass attacks", explanation="Subword tokenization can be bypassed with crafted inputs", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML01", tags={"ai", "ml", "nlp", "subword", "bypass"}, references=["https://aclanthology.org/2020.emnlp-main.463/"]),
    Rule(rule_id="AIML318", name="bpe-manipulation", description="BPE manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="BPE encoding - validate encoding parameters to prevent manipulation", explanation="Byte Pair Encoding can be manipulated through parameter tampering", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "bpe", "manipulation"}, references=["https://arxiv.org/abs/1508.07909"]),
    Rule(rule_id="AIML319", name="wordpiece-attack-vectors", description="WordPiece attack vectors", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="WordPiece tokenization - validate tokens to prevent attack vectors", explanation="WordPiece tokenization vulnerable to adversarial token sequences", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "wordpiece", "attack"}, references=["https://arxiv.org/abs/1609.08144"]),
    Rule(rule_id="AIML320", name="sentencepiece-vulnerabilities", description="SentencePiece vulnerabilities", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="SentencePiece - validate model and inputs to prevent vulnerabilities", explanation="SentencePiece models should be validated for integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "sentencepiece", "vulnerability"}, references=["https://arxiv.org/abs/1808.06226"]),
    Rule(rule_id="AIML321", name="text-normalization-bypass", description="Text normalization bypass", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Text normalization - validate Unicode handling to prevent bypass", explanation="Text normalization can be bypassed using Unicode tricks", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-20", owasp_mapping="ML01", tags={"ai", "ml", "nlp", "normalization", "bypass"}, references=["https://unicode.org/reports/tr15/"]),
    Rule(rule_id="AIML322", name="stopword-removal-manipulation", description="Stop word removal manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Stop word removal - validate custom stop word lists to prevent manipulation", explanation="Custom stop word lists can be manipulated to affect model behavior", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "stopwords", "manipulation"}, references=["https://nlp.stanford.edu/IR-book/html/htmledition/dropping-common-terms-stop-words-1.html"]),
    Rule(rule_id="AIML323", name="stemming-lemmatization-attacks", description="Stemming/lemmatization attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Stemming/lemmatization - validate models to prevent attacks", explanation="Stemming and lemmatization models can be manipulated", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "stemming", "lemmatization"}, references=["https://nlp.stanford.edu/IR-book/html/htmledition/stemming-and-lemmatization-1.html"]),
    Rule(rule_id="AIML324", name="ner-injection", description="NER injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="NER - validate inputs to prevent entity injection attacks", explanation="Named Entity Recognition can be manipulated with crafted inputs", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML01", tags={"ai", "ml", "nlp", "ner", "injection"}, references=["https://arxiv.org/abs/2004.05986"]),
    Rule(rule_id="AIML325", name="pos-tagging-manipulation", description="POS tagging manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="POS tagging - validate tags to prevent manipulation", explanation="Part-of-speech tags can be manipulated through adversarial inputs", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "pos", "manipulation"}, references=["https://aclanthology.org/N19-1165/"]),
    Rule(rule_id="AIML326", name="dependency-parsing-poisoning", description="Dependency parsing poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Dependency parsing - validate parse trees to prevent poisoning", explanation="Dependency parsing can be poisoned through crafted sentences", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "dependency", "poisoning"}, references=["https://arxiv.org/abs/1901.10513"]),
    Rule(rule_id="AIML327", name="sentiment-analysis-bias", description="Sentiment analysis bias", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Sentiment analysis - validate for bias and fairness", explanation="Sentiment models should be validated for demographic bias", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-754", owasp_mapping="ML06", tags={"ai", "ml", "nlp", "sentiment", "bias"}, references=["https://arxiv.org/abs/1805.04508"]),
    Rule(rule_id="AIML328", name="text-classification-backdoors", description="Text classification backdoors", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Text classification - validate training data to prevent backdoor attacks", explanation="Text classifiers vulnerable to backdoor poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-912", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "classification", "backdoor"}, references=["https://arxiv.org/abs/1809.00152"]),
    Rule(rule_id="AIML329", name="sequence-labeling-attacks", description="Sequence labeling attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Sequence labeling - validate labels to prevent attacks", explanation="Sequence labeling models can be manipulated through adversarial sequences", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "sequence", "attack"}, references=["https://arxiv.org/abs/1908.05616"]),
    Rule(rule_id="AIML330", name="coreference-resolution-manipulation", description="Coreference resolution manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="Coreference resolution - validate resolutions to prevent manipulation", explanation="Coreference resolution can be manipulated to change meaning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "coreference", "manipulation"}, references=["https://arxiv.org/abs/1906.07045"]),
    # Phase 3.2.2: Transformer Architectures (AIML331-AIML342)
    Rule(rule_id="AIML331", name="bert-finetuning-injection", description="BERT fine-tuning injection", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="BERT fine-tuning - validate training data to prevent injection attacks", explanation="BERT fine-tuning vulnerable to data poisoning", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "bert", "finetuning"}, references=["https://arxiv.org/abs/1810.04805"]),
    Rule(rule_id="AIML332", name="gpt-prompt-engineering-attacks", description="GPT prompt engineering attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.CRITICAL, message_template="GPT prompt engineering - sanitize prompts to prevent attacks", explanation="GPT models vulnerable to prompt injection and jailbreaking", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML01", tags={"ai", "ml", "nlp", "gpt", "prompt"}, references=["https://arxiv.org/abs/2302.12173"]),
    Rule(rule_id="AIML333", name="t5-encoder-decoder-manipulation", description="T5 encoder-decoder manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="T5 encoder-decoder - validate inputs to prevent manipulation", explanation="T5 encoder-decoder architecture vulnerable to input manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "t5", "manipulation"}, references=["https://arxiv.org/abs/1910.10683"]),
    Rule(rule_id="AIML334", name="bart-denoising-poisoning", description="BART denoising poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="BART denoising - validate training data to prevent poisoning", explanation="BART denoising can be poisoned through corrupted training data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "bart", "poisoning"}, references=["https://arxiv.org/abs/1910.13461"]),
    Rule(rule_id="AIML335", name="roberta-masked-lm", description="RoBERTa masked LM", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="RoBERTa MLM - validate masked tokens to prevent manipulation", explanation="RoBERTa masked language modeling vulnerable to token manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "roberta", "mlm"}, references=["https://arxiv.org/abs/1907.11692"]),
    Rule(rule_id="AIML336", name="electra-attacks", description="ELECTRA attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ELECTRA - validate discriminator/generator to prevent attacks", explanation="ELECTRA's discriminator-generator architecture vulnerable to adversarial attacks", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "electra", "attack"}, references=["https://arxiv.org/abs/2003.10555"]),
    Rule(rule_id="AIML337", name="xlnet-permutation-lm", description="XLNet permutation LM", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="XLNet permutation LM - validate permutations to prevent manipulation", explanation="XLNet permutation language modeling can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "xlnet", "permutation"}, references=["https://arxiv.org/abs/1906.08237"]),
    Rule(rule_id="AIML338", name="albert-parameter-sharing-risks", description="ALBERT parameter sharing risks", category=RuleCategory.SECURITY, severity=RuleSeverity.LOW, message_template="ALBERT parameter sharing - validate shared parameters for security", explanation="ALBERT's parameter sharing can propagate vulnerabilities across layers", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "albert", "parameter"}, references=["https://arxiv.org/abs/1909.11942"]),
    Rule(rule_id="AIML339", name="distilbert-knowledge-distillation", description="DistilBERT knowledge distillation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="DistilBERT - validate teacher model to prevent vulnerability inheritance", explanation="DistilBERT can inherit vulnerabilities from teacher model", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "distilbert", "distillation"}, references=["https://arxiv.org/abs/1910.01108"]),
    Rule(rule_id="AIML340", name="deberta-disentangled-attention", description="DeBERTa disentangled attention", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="DeBERTa disentangled attention - validate attention mechanisms", explanation="DeBERTa's disentangled attention vulnerable to manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "nlp", "deberta", "attention"}, references=["https://arxiv.org/abs/2006.03654"]),
    Rule(rule_id="AIML341", name="longformer-sliding-window-attacks", description="Longformer sliding window attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Longformer sliding window - validate window size to prevent attacks", explanation="Longformer's sliding window mechanism vulnerable to resource exhaustion", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-400", owasp_mapping="ML09", tags={"ai", "ml", "nlp", "longformer", "window"}, references=["https://arxiv.org/abs/2004.05150"]),
    Rule(rule_id="AIML342", name="bigbird-sparse-attention-manipulation", description="BigBird sparse attention manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="BigBird sparse attention - validate attention patterns to prevent manipulation", explanation="BigBird's sparse attention patterns can be manipulated", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML04", tags={"ai", "ml", "nlp", "bigbird", "attention"}, references=["https://arxiv.org/abs/2007.14062"]),
    # Phase 3.2.3: Embeddings & Representations (AIML343-AIML350)
    Rule(rule_id="AIML343", name="word2vec-poisoning", description="Word2Vec poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Word2Vec - validate training corpus to prevent poisoning attacks", explanation="Word2Vec embeddings can be poisoned through corrupted training data", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "word2vec", "poisoning"}, references=["https://arxiv.org/abs/1301.3781"]),
    Rule(rule_id="AIML344", name="glove-embedding-manipulation", description="GloVe embedding manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="GloVe embeddings - verify integrity before loading to prevent manipulation", explanation="GloVe embeddings should be verified for integrity", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-494", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "glove", "manipulation"}, references=["https://nlp.stanford.edu/projects/glove/"]),
    Rule(rule_id="AIML345", name="fasttext-subword-attacks", description="FastText subword attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="FastText subword - validate subword embeddings to prevent attacks", explanation="FastText subword embeddings vulnerable to adversarial subwords", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "fasttext", "subword"}, references=["https://arxiv.org/abs/1607.04606"]),
    Rule(rule_id="AIML346", name="elmo-contextualized-embedding-injection", description="ELMo contextualized embedding injection", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="ELMo embeddings - validate context to prevent injection attacks", explanation="ELMo contextualized embeddings vulnerable to context injection", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-74", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "elmo", "injection"}, references=["https://arxiv.org/abs/1802.05365"]),
    Rule(rule_id="AIML347", name="sentence-bert-manipulation", description="Sentence-BERT manipulation", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Sentence-BERT - validate sentence encodings to prevent manipulation", explanation="Sentence-BERT encodings can be manipulated through adversarial sentences", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "sbert", "manipulation"}, references=["https://arxiv.org/abs/1908.10084"]),
    Rule(rule_id="AIML348", name="universal-sentence-encoder-risks", description="Universal Sentence Encoder risks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Universal Sentence Encoder - validate inputs to prevent risks", explanation="Universal Sentence Encoder vulnerable to adversarial inputs", fix_applicability=FixApplicability.SAFE, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "use", "risk"}, references=["https://arxiv.org/abs/1803.11175"]),
    Rule(rule_id="AIML349", name="doc2vec-document-poisoning", description="Doc2Vec document poisoning", category=RuleCategory.SECURITY, severity=RuleSeverity.HIGH, message_template="Doc2Vec - validate document corpus to prevent poisoning attacks", explanation="Doc2Vec embeddings can be poisoned through document injection", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "doc2vec", "poisoning"}, references=["https://arxiv.org/abs/1405.4053"]),
    Rule(rule_id="AIML350", name="graph-embedding-attacks", description="Graph embedding attacks", category=RuleCategory.SECURITY, severity=RuleSeverity.MEDIUM, message_template="Graph embeddings - validate graph structure to prevent attacks", explanation="Graph embeddings vulnerable to graph structure manipulation", fix_applicability=FixApplicability.MANUAL, cwe_mapping="CWE-345", owasp_mapping="ML03", tags={"ai", "ml", "nlp", "graph", "embedding"}, references=["https://arxiv.org/abs/1709.05584"]),
]
