import asyncio
import logging
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.scan_tasks.scan_auth_logs")
def scan_auth_logs():
    from app.services.firewall_manager import FirewallManager

    async def _scan():
        fw = FirewallManager()
        blocked = await fw.auto_block_brute_force()
        if blocked:
            logger.warning(f"Auto-blocked {len(blocked)} IPs for brute force: {blocked}")
        return {"blocked": blocked}

    return asyncio.run(_scan())


@celery_app.task(name="app.tasks.scan_tasks.run_malware_scan")
def run_malware_scan(username: str | None = None):
    from app.services.imunify_manager import ImunifyManager

    async def _scan():
        imunify = ImunifyManager()
        if username:
            path = f"/home/{username}"
        else:
            path = "/home"
        result = await imunify.scan_path(path)
        logger.info(f"Malware scan triggered for {path}: {result}")
        return result

    return asyncio.run(_scan())


@celery_app.task(name="app.tasks.scan_tasks.analyze_access_logs")
def analyze_access_logs(log_path: str = "/var/log/nginx/access.log"):
    from app.ai.anomaly_detector import LogAnomalyDetector

    detector = LogAnomalyDetector()
    events = []
    try:
        with open(log_path) as f:
            for line in f:
                event = detector.ingest_access_log_line(line.strip())
                if event:
                    events.append({
                        "severity": event.severity,
                        "category": event.category,
                        "description": event.description,
                        "source_ip": event.source_ip,
                        "suggested_action": event.suggested_action,
                    })
    except FileNotFoundError:
        pass

    logger.info(f"Access log analysis complete: {len(events)} anomalies found")
    return {"anomalies": events}
