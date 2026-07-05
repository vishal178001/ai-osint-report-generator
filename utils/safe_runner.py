from concurrent.futures import ThreadPoolExecutor, TimeoutError

from utils.logger import logger
from config.settings import COLLECTOR_TIMEOUT


def safe_collect(name, collector_function, target):
    logger.info(f"Starting collector: {name}")

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(collector_function, target)

    try:
        result = future.result(timeout=COLLECTOR_TIMEOUT)

        logger.info(
            f"Collector completed successfully: {name}"
        )

        return result, "success"

    except TimeoutError:
        logger.error(
            f"Collector timed out: {name} | "
            f"Timeout: {COLLECTOR_TIMEOUT} seconds"
        )

        print(
            f"[-] {name} collector timed out after "
            f"{COLLECTOR_TIMEOUT} seconds. "
            "Continuing with remaining collectors."
        )

        return {}, "timeout"

    except Exception as error:
        logger.error(
            f"Collector failed: {name} | Error: {error}"
        )

        print(
            f"[-] {name} collector failed. "
            "Continuing with remaining collectors."
        )

        return {}, "failed"

    finally:
        executor.shutdown(wait=False, cancel_futures=True)

