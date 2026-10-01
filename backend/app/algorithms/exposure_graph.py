from __future__ import annotations

from collections import defaultdict, deque
from itertools import combinations
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.models import (
    Account,
    AccountConnection,
    AccountPhoneNumber,
    AccountRecoveryEmail,
    ConnectionType,
    User,
)

EDGE_WEIGHTS: dict[str, int] = {
    "RECOVERY_EMAIL": 3,
    "RECOVERY_PHONE": 3,
    "SHARED_PASSWORD": 4,
    "SSO": 4,
    "CONNECTED_SERVICE": 2,
    "OTHER": 1,
}


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _sorted_pair(first: str, second: str) -> tuple[str, str]:
    return (first, second) if first <= second else (second, first)


def _connected_components(adjacency: dict[str, set[str]], nodes: list[str]) -> list[dict[str, Any]]:
    visited: set[str] = set()
    components: list[list[str]] = []
    for node in sorted(nodes):
        if node in visited:
            continue
        queue = deque([node])
        visited.add(node)
        component: list[str] = []
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        components.append(sorted(component))

    ordered = sorted(components, key=lambda item: (len(item), item))
    result: list[dict[str, Any]] = []
    for index, component in enumerate(reversed(ordered), start=1):
        result.append({"component_id": index, "account_ids": component, "size": len(component)})
    return result


def _find_articulation_points(adjacency: dict[str, set[str]], nodes: list[str]) -> list[dict[str, Any]]:
    if len(nodes) <= 1:
        return []

    articulation_points: list[dict[str, Any]] = []
    for node in sorted(nodes):
        remaining_nodes = [item for item in nodes if item != node]
        if not remaining_nodes:
            continue
        visited: set[str] = set()
        component_count = 0
        for candidate in sorted(remaining_nodes):
            if candidate in visited:
                continue
            component_count += 1
            stack = [candidate]
            visited.add(candidate)
            while stack:
                current = stack.pop()
                for neighbor in sorted(adjacency.get(current, set())):
                    if neighbor == node or neighbor in visited:
                        continue
                    visited.add(neighbor)
                    stack.append(neighbor)
        if component_count > 1:
            articulation_points.append(
                {
                    "account_id": node,
                    "affected_component_size": len(remaining_nodes),
                    "reason": "Removing this account disconnects other accounts in the exposure graph.",
                }
            )
    return articulation_points


def _reachable_accounts(adjacency: dict[str, set[str]], start: str) -> set[str]:
    visited: set[str] = set()
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor in visited or neighbor == start:
                continue
            visited.add(neighbor)
            queue.append(neighbor)
    return visited


def _compute_metrics(
    adjacency: dict[str, set[str]],
    nodes: list[str],
    components: list[dict[str, Any]],
    articulation_points: list[dict[str, Any]],
    account_lookup: dict[str, Any],
) -> list[dict[str, Any]]:
    component_lookup: dict[str, int] = {}
    for component in components:
        for account_id in component["account_ids"]:
            component_lookup[account_id] = component["component_id"]

    articulation_ids = {item["account_id"] for item in articulation_points}
    metrics: list[dict[str, Any]] = []
    for account_id in sorted(nodes):
        account = account_lookup[account_id]
        degree = len(adjacency.get(account_id, set()))
        normalized_degree = degree / (len(nodes) - 1) if len(nodes) > 1 else 0.0
        reachable = _reachable_accounts(adjacency, account_id)
        metrics.append(
            {
                "account_id": account_id,
                "service": (account.service.name if account.service else None),
                "display_name": account.display_name or account.account_identifier,
                "degree": degree,
                "normalized_degree": round(normalized_degree, 4),
                "component_id": component_lookup.get(account_id, 1),
                "component_size": next(item["size"] for item in components if account_id in item["account_ids"]),
                "reachable_accounts": len(reachable),
                "is_articulation_point": account_id in articulation_ids,
            }
        )
    return metrics


def _add_edge(
    edge_map: dict[tuple[str, str, str], dict[str, Any]],
    adjacency: dict[str, set[str]],
    source: str,
    target: str,
    edge_type: str,
) -> None:
    if source == target:
        return
    ordered_pair = _sorted_pair(source, target)
    key = (edge_type, ordered_pair[0], ordered_pair[1])
    if key in edge_map:
        return
    edge_map[key] = {
        "source": source,
        "target": target,
        "type": edge_type,
        "weight": EDGE_WEIGHTS.get(edge_type, 1),
    }
    adjacency.setdefault(source, set()).add(target)
    adjacency.setdefault(target, set()).add(source)


def build_exposure_graph(db: Session, user_id: str) -> dict[str, Any]:
    user = db.get(User, user_id)
    if not user:
        raise ValueError("USER_NOT_FOUND")

    accounts = db.scalars(
        select(Account)
        .where(Account.user_id == user_id)
        .where(Account.is_active.is_(True))
        .options(selectinload(Account.service))
        .order_by(Account.created_at.asc())
    ).all()

    account_lookup = {account.id: account for account in accounts}
    node_ids = sorted(account_lookup.keys())
    adjacency: dict[str, set[str]] = {account_id: set() for account_id in node_ids}
    edge_map: dict[tuple[str, str, str], dict[str, Any]] = {}

    if node_ids:
        account_id_set = set(node_ids)
        explicit_connections = db.scalars(
            select(AccountConnection).where(
                (AccountConnection.source_account_id.in_(account_id_set)) | (AccountConnection.target_account_id.in_(account_id_set))
            ).where(AccountConnection.is_active.is_(True))
        ).all()
        for connection in explicit_connections:
            if connection.source_account_id not in account_lookup or connection.target_account_id not in account_lookup:
                continue
            edge_type = _enum_value(connection.connection_type)
            if connection.source_account_id == connection.target_account_id:
                continue
            _add_edge(edge_map, adjacency, connection.source_account_id, connection.target_account_id, edge_type)

        recovery_links = db.scalars(
            select(AccountRecoveryEmail).where(AccountRecoveryEmail.account_id.in_(account_id_set))
        ).all()
        grouped_recovery: dict[str, list[str]] = defaultdict(list)
        for link in recovery_links:
            grouped_recovery[link.recovery_email_id].append(link.account_id)
        for accounts_for_email in grouped_recovery.values():
            if len(accounts_for_email) < 2:
                continue
            for first, second in combinations(sorted(set(accounts_for_email)), 2):
                _add_edge(edge_map, adjacency, first, second, "RECOVERY_EMAIL")

        phone_links = db.scalars(
            select(AccountPhoneNumber).where(AccountPhoneNumber.account_id.in_(account_id_set))
        ).all()
        grouped_phone: dict[str, list[str]] = defaultdict(list)
        for link in phone_links:
            grouped_phone[link.phone_number_id].append(link.account_id)
        for accounts_for_phone in grouped_phone.values():
            if len(accounts_for_phone) < 2:
                continue
            for first, second in combinations(sorted(set(accounts_for_phone)), 2):
                _add_edge(edge_map, adjacency, first, second, "RECOVERY_PHONE")

        grouped_password: dict[str, list[str]] = defaultdict(list)
        for account_id in node_ids:
            account = account_lookup[account_id]
            if account.password_reuse_group_id:
                grouped_password[account.password_reuse_group_id].append(account_id)
        for accounts_for_group in grouped_password.values():
            if len(accounts_for_group) < 2:
                continue
            for first, second in combinations(sorted(set(accounts_for_group)), 2):
                _add_edge(edge_map, adjacency, first, second, "SHARED_PASSWORD")

    nodes = []
    for account_id in node_ids:
        account = account_lookup[account_id]
        nodes.append(
            {
                "id": account.id,
                "service_id": account.service_id,
                "service_name": account.service.name if account.service else None,
                "display_name": account.display_name or account.account_identifier,
                "status": _enum_value(account.status),
                "is_active": account.is_active,
                "two_factor_enabled": account.two_factor_enabled,
                "last_activity": account.last_activity.isoformat() if account.last_activity else None,
            }
        )

    edges = [
        {
            "source": details["source"],
            "target": details["target"],
            "type": details["type"],
            "weight": details["weight"],
        }
        for _, details in sorted(edge_map.items(), key=lambda item: (item[1]["source"], item[1]["target"], item[1]["type"]))
    ]
    components = _connected_components(adjacency, node_ids)
    articulation_points = _find_articulation_points(adjacency, node_ids)
    structural_metrics = _compute_metrics(adjacency, node_ids, components, articulation_points, account_lookup)
    high_connectivity_accounts = [
        {
            "account_id": metric["account_id"],
            "degree": metric["degree"],
            "normalized_degree": metric["normalized_degree"],
            "service": metric["service"],
            "display_name": metric["display_name"],
        }
        for metric in sorted(structural_metrics, key=lambda item: (-item["degree"], -item["normalized_degree"], item["account_id"]))[:5]
    ]

    return {
        "user_id": user_id,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(node_ids),
        "edge_count": len(edges),
        "connected_components": components,
        "high_connectivity_accounts": high_connectivity_accounts,
        "articulation_points": articulation_points,
        "structural_metrics": structural_metrics,
        "largest_component_size": max((item["size"] for item in components), default=0),
        "component_count": len(components),
    }


def find_exposure_path(graph_payload: dict[str, Any], source_account_id: str, target_account_id: str) -> dict[str, Any]:
    existing_nodes = {node["id"] for node in graph_payload["nodes"]}
    if source_account_id not in existing_nodes or target_account_id not in existing_nodes:
        return {"exists": False, "path": [], "edges": [], "hops": 0}
    if source_account_id == target_account_id:
        return {"exists": False, "path": [], "edges": [], "hops": 0}

    adjacency: dict[str, set[str]] = defaultdict(set)
    edge_types: dict[tuple[str, str], list[str]] = defaultdict(list)
    for edge in graph_payload["edges"]:
        a = edge["source"]
        b = edge["target"]
        adjacency[a].add(b)
        adjacency[b].add(a)
        pair = _sorted_pair(a, b)
        edge_types[(pair[0], pair[1])].append(edge["type"])

    queue = deque([source_account_id])
    parents: dict[str, str | None] = {source_account_id: None}
    while queue:
        current = queue.popleft()
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor in parents:
                continue
            parents[neighbor] = current
            if neighbor == target_account_id:
                queue.clear()
                break
            queue.append(neighbor)
        if target_account_id in parents:
            break

    if target_account_id not in parents:
        return {"exists": False, "path": [], "edges": [], "hops": 0}

    path_ids: list[str] = []
    current = target_account_id
    while current is not None:
        path_ids.append(current)
        current = parents[current]
    path_ids.reverse()

    path_edges: list[dict[str, Any]] = []
    for index in range(len(path_ids) - 1):
        source = path_ids[index]
        target = path_ids[index + 1]
        pair = _sorted_pair(source, target)
        available_types = edge_types.get((pair[0], pair[1]), [])
        chosen_type = sorted(available_types, key=lambda item: (-EDGE_WEIGHTS.get(item, 1), item))[0] if available_types else "OTHER"
        path_edges.append({"source": source, "target": target, "type": chosen_type})

    return {
        "exists": True,
        "path": [{"account_id": account_id} for account_id in path_ids],
        "edges": [{"type": edge["type"]} for edge in path_edges],
        "hops": len(path_ids) - 1,
    }
