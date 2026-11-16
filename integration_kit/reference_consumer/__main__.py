"""Command line for the reference consumer.

    python -m integration_kit.reference_consumer pull       # fetch new packs (verify + validate) into the inbox
    python -m integration_kit.reference_consumer run        # hunt the inbox on your platform, post feedback
    python -m integration_kit.reference_consumer cycle [--every 900]   # pull + run, once or forever
    python -m integration_kit.reference_consumer receive --port 8088   # push endpoint (behind your TLS proxy)
    python -m integration_kit.reference_consumer convert pack.json --platform splunk   # print queries, no network

Settings come from HC_KIT_* environment variables (integration_kit/consumer.env.example).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import httpx

from integration_kit.reference_consumer.accounts import load_directory
from integration_kit.reference_consumer.adapters import Adapter
from integration_kit.reference_consumer.adapters.elastic import ElasticAdapter
from integration_kit.reference_consumer.adapters.splunk import SplunkAdapter
from integration_kit.reference_consumer.adapters.wazuh import WazuhAdapter
from integration_kit.reference_consumer.client import HuntCompilerClient
from integration_kit.reference_consumer.config import KitConfig
from integration_kit.reference_consumer.convert import to_elastic, to_splunk
from integration_kit.reference_consumer.placeholders import substitute_sigma
from integration_kit.reference_consumer.receiver import serve
from integration_kit.reference_consumer.runner import Runner
from integration_kit.reference_consumer.state import State
from integration_kit.reference_consumer.validate import validate_pack

log = logging.getLogger("hc_kit")


def make_adapter(cfg: KitConfig, http: httpx.Client) -> Adapter:
    if cfg.platform == "wazuh":
        return WazuhAdapter(http, url=cfg.platform_url, index=cfg.platform_index, user=cfg.platform_user,
                            password=cfg.platform_password)  # fmt: skip
    if cfg.platform == "elastic":
        return ElasticAdapter(http, url=cfg.platform_url, index=cfg.platform_index, api_key=cfg.platform_token,
                              language=cfg.elastic_language, pipeline=cfg.elastic_pipeline,
                              max_hits=cfg.max_hits)  # fmt: skip
    return SplunkAdapter(http, url=cfg.platform_url, token=cfg.platform_token, index=cfg.platform_index,
                         xml_source=cfg.splunk_xml_source)  # fmt: skip


def build_runner(cfg: KitConfig, hc_http: httpx.Client, platform_http: httpx.Client) -> Runner:
    client = HuntCompilerClient(hc_http, base_url=cfg.base_url, api_token=cfg.api_token, hmac_secret=cfg.hmac_secret,
                                tenant=cfg.tenant)  # fmt: skip
    directory = load_directory(cfg.directory_csv) if cfg.directory_csv else None
    return Runner(cfg, make_adapter(cfg, platform_http), State(cfg.state_dir), client, directory)


def _convert(path: str, platform: str) -> int:
    pack = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_pack(pack)
    for task in pack["internal_hunting_tasks"]:
        print(f"### {task['task_id']}")
        if platform == "wazuh":
            print(json.dumps((task.get("compiled_queries") or {}).get("wazuh_es_dsl"), indent=2))
            continue
        try:
            sigma = substitute_sigma(task["sigma_yaml"], {})
        except KeyError as exc:
            print(f"(needs a value for ${{HC_{exc.args[0]}}}; showing the rule unsubstituted)")
            sigma = task["sigma_yaml"]
        print(to_splunk(sigma) if platform == "splunk" else to_elastic(sigma))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m integration_kit.reference_consumer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("pull")
    sub.add_parser("run")
    cycle = sub.add_parser("cycle")
    cycle.add_argument("--every", type=int, default=0, help="seconds between cycles; 0 = once")
    receive = sub.add_parser("receive")
    receive.add_argument("--host", default="127.0.0.1")
    receive.add_argument("--port", type=int, default=8088)
    receive.add_argument("--path", default="/huntcompiler")
    conv = sub.add_parser("convert")
    conv.add_argument("pack")
    conv.add_argument("--platform", choices=("wazuh", "elastic", "splunk"), default="splunk")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.command == "convert":
        return _convert(args.pack, args.platform)
    cfg = KitConfig.from_env()
    if args.command == "receive":
        serve(args.host, args.port, secret=cfg.hmac_secret, state=State(cfg.state_dir), path=args.path)
        return 0
    with (
        httpx.Client(timeout=30.0, verify=cfg.hc_verify) as hc_http,
        httpx.Client(timeout=120.0, verify=cfg.platform_verify) as p_http,
    ):
        runner = build_runner(cfg, hc_http, p_http)
        while True:
            if args.command in ("pull", "cycle"):
                log.info("pull: %s", runner.pull())
            if args.command in ("run", "cycle"):
                runner.run_inbox()
            if args.command != "cycle" or args.every <= 0:
                return 0
            time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main())
