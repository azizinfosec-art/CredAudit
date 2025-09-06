import os, yaml
from dataclasses import dataclass, field
from typing import List, Optional
DEFAULT_CONFIG_PATH = "config.yaml"
@dataclass
class RuleToggles:
    enable_password_assignment: bool = True
    enable_jwt: bool = True
    enable_private_keys: bool = True
    enable_cloud_tokens: bool = True
    enable_entropy: bool = True
@dataclass
class Config:
    include_ext: List[str] = field(default_factory=lambda: [".txt",".json",".env",".docx",".pdf",".xlsx",".har"])
    include_glob: List[str] = field(default_factory=list)
    exclude_glob: List[str] = field(default_factory=lambda: ["**/.git/**","**/__pycache__/**","**/node_modules/**"])
    workers: Optional[int] = None
    threads: int = 8
    entropy_min_length: int = 20
    entropy_threshold: float = 4.0
    cache_file: str = ".credaudit_cache.json"
    rules: RuleToggles = field(default_factory=RuleToggles)
    @staticmethod
    def from_yaml(path: str) -> "Config":
        if not os.path.exists(path):
            return Config()
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules_data = data.get("rules", {})
        rules = RuleToggles(**rules_data) if isinstance(rules_data, dict) else RuleToggles()
        return Config(
            include_ext=[e.lower() for e in data.get("include_ext", [".txt",".json",".env",".docx",".pdf",".xlsx",".har"])],
            include_glob=data.get("include_glob", []) or [],
            exclude_glob=data.get("exclude_glob", []) or ["**/.git/**","**/__pycache__/**","**/node_modules/**"],
            workers=data.get("workers"),
            threads=int(data.get("threads", 8)),
            entropy_min_length=int(data.get("entropy_min_length", 20)),
            entropy_threshold=float(data.get("entropy_threshold", 4.0)),
            cache_file=str(data.get("cache_file", ".credaudit_cache.json")),
            rules=rules,
        )
    def merge_cli_overrides(self, args: dict) -> None:
        if args.get("include_ext"):
            self.include_ext = [e.lower() if e.startswith(".") else "."+e.lower() for e in args["include_ext"]]
        if args.get("include_glob"): self.include_glob = list(args["include_glob"])
        if args.get("exclude_glob"): self.exclude_glob = list(args["exclude_glob"])
        if args.get("threads") is not None: self.threads = int(args["threads"])
        if args.get("workers") is not None: self.workers = int(args["workers"])
        if args.get("entropy_min_length") is not None: self.entropy_min_length = int(args["entropy_min_length"])
        if args.get("entropy_threshold") is not None: self.entropy_threshold = float(args["entropy_threshold"])
        if args.get("cache_file") is not None: self.cache_file = str(args["cache_file"])
