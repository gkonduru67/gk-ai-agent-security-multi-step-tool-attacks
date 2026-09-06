#!/usr/bin/env python3
"""Import repair launcher for UTA GPT-OSS server transport v7.50A.

Fixes dynamic loading of benign_pipeline_v6.py by registering the module in
sys.modules before exec_module(). This is required by Python dataclasses during
class decoration. All experiment logic remains in uta_gpt_oss_transport_v7_50A_server.py.
"""
from __future__ import annotations
import argparse, importlib.util, sys
from pathlib import Path

def registered_load_file(path: Path, name: str):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Cannot load module: {path}')
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name,None)
        raise
    return module

def load_base(path: Path):
    spec=importlib.util.spec_from_file_location('uta_v750a_server_base',path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Cannot load base runner: {path}')
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--project-root',required=True,type=Path)
    ap.add_argument('--backend',choices=['server'],default='server')
    ap.add_argument('--server-url',default='http://127.0.0.1:8080')
    ap.add_argument('--out-dir',required=True,type=Path)
    ap.add_argument('--fixture-dir',required=True,type=Path)
    ap.add_argument('--fixture-manifest',required=True,type=Path)
    ap.add_argument('--max-tool-hops',type=int,default=4)
    ap.add_argument('--seed',type=int,default=123)
    args=ap.parse_args()
    base_path=Path(__file__).resolve().with_name('uta_gpt_oss_transport_v7_50A_server.py')
    if not base_path.is_file():
        raise SystemExit(f'Base server runner must be beside this launcher: {base_path}')
    base=load_base(base_path)
    base.load_file=registered_load_file
    # Manifest should identify the actually executed repair launcher.
    base.__file__=str(Path(__file__).resolve())
    sys.argv=[str(Path(__file__).resolve()),
      '--project-root',str(args.project_root),'--backend',args.backend,
      '--server-url',args.server_url,'--out-dir',str(args.out_dir),
      '--fixture-dir',str(args.fixture_dir),'--fixture-manifest',str(args.fixture_manifest),
      '--max-tool-hops',str(args.max_tool_hops),'--seed',str(args.seed)]
    return base.main()
if __name__=='__main__':
    raise SystemExit(main())
