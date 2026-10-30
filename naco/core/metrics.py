"""A tiny Prometheus text-format registry (no client library needed)."""
from __future__ import annotations

from collections.abc import Sequence


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def _labels(names: Sequence[str], values: Sequence[str], extra: str = "") -> str:
    parts = [f'{n}="{_escape(v)}"' for n, v in zip(names, values, strict=True)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


class _Metric:
    kind = ""

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> None:
        self.name, self.help, self.labelnames = name, help_, tuple(labelnames)

    def _key(self, labels: dict[str, str]) -> tuple[str, ...]:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"{self.name}: expected labels {self.labelnames}, got {tuple(labels)}")
        return tuple(str(labels[n]) for n in self.labelnames)

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]

    def render(self) -> list[str]:
        raise NotImplementedError


class Counter(_Metric):
    kind = "counter"

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help_, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = self._key(labels)
        self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        return self._values.get(self._key(labels), 0.0)

    def render(self) -> list[str]:
        return [f"{self.name}{_labels(self.labelnames, k)} {v:g}" for k, v in sorted(self._values.items())]


class Gauge(_Metric):
    kind = "gauge"

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> None:
        super().__init__(name, help_, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        self._values[self._key(labels)] = value

    def value(self, **labels: str) -> float:
        return self._values.get(self._key(labels), 0.0)

    def render(self) -> list[str]:
        return [f"{self.name}{_labels(self.labelnames, k)} {v:g}" for k, v in sorted(self._values.items())]


class Histogram(_Metric):
    kind = "histogram"
    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

    def __init__(self, name: str, help_: str, labelnames: Sequence[str] = (),
                 buckets: Sequence[float] = DEFAULT_BUCKETS) -> None:
        super().__init__(name, help_, labelnames)
        self.buckets = tuple(sorted(buckets))
        self._data: dict[tuple[str, ...], tuple[list[int], float, int]] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        counts, total, n = self._data.get(key, ([0] * len(self.buckets), 0.0, 0))
        for i, bound in enumerate(self.buckets):
            if value <= bound:
                counts[i] += 1
        self._data[key] = (counts, total + value, n + 1)

    def render(self) -> list[str]:
        out = []
        for key, (counts, total, n) in sorted(self._data.items()):
            for bound, c in zip(self.buckets, counts, strict=True):
                le = f'le="{bound:g}"'
                out.append(f"{self.name}_bucket{_labels(self.labelnames, key, le)} {c}")
            inf = 'le="+Inf"'
            out.append(f"{self.name}_bucket{_labels(self.labelnames, key, inf)} {n}")
            out.append(f"{self.name}_sum{_labels(self.labelnames, key)} {total:g}")
            out.append(f"{self.name}_count{_labels(self.labelnames, key)} {n}")
        return out


class Registry:
    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}

    def _add(self, metric: _Metric) -> _Metric:
        if metric.name in self._metrics:
            raise ValueError(f"metric {metric.name} already registered")
        self._metrics[metric.name] = metric
        return metric

    def counter(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> Counter:
        return self._add(Counter(name, help_, labelnames))  # type: ignore[return-value]

    def gauge(self, name: str, help_: str, labelnames: Sequence[str] = ()) -> Gauge:
        return self._add(Gauge(name, help_, labelnames))  # type: ignore[return-value]

    def histogram(self, name: str, help_: str, labelnames: Sequence[str] = (),
                  buckets: Sequence[float] = Histogram.DEFAULT_BUCKETS) -> Histogram:
        return self._add(Histogram(name, help_, labelnames, buckets))  # type: ignore[return-value]

    def render(self) -> str:
        lines: list[str] = []
        for metric in self._metrics.values():
            lines += metric.header() + metric.render()
        return "\n".join(lines) + "\n"


REGISTRY = Registry()
