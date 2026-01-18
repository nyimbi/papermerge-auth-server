# (c) Copyright Datacraft, 2026
"""Condition evaluators for ABAC rules."""
import logging
import re
from datetime import datetime, time
from typing import Any, Callable
from ipaddress import ip_address, ip_network

from .models import SubjectAttributes, ResourceAttributes, EnvironmentAttributes

logger = logging.getLogger(__name__)


class ConditionOperator:
	"""Supported condition operators."""
	EQUALS = 'eq'
	NOT_EQUALS = 'neq'
	GREATER_THAN = 'gt'
	GREATER_EQUAL = 'gte'
	LESS_THAN = 'lt'
	LESS_EQUAL = 'lte'
	IN = 'in'
	NOT_IN = 'not_in'
	CONTAINS = 'contains'
	NOT_CONTAINS = 'not_contains'
	STARTS_WITH = 'starts_with'
	ENDS_WITH = 'ends_with'
	MATCHES = 'matches'  # regex
	EXISTS = 'exists'
	NOT_EXISTS = 'not_exists'
	BETWEEN = 'between'
	ANY_OF = 'any_of'  # list intersection
	ALL_OF = 'all_of'  # list subset
	NONE_OF = 'none_of'  # list disjoint
	IP_IN_RANGE = 'ip_in_range'
	TIME_BETWEEN = 'time_between'


class ConditionEvaluator:
	"""Evaluates ABAC conditions against attributes."""

	def __init__(self):
		self._operators: dict[str, Callable] = {
			ConditionOperator.EQUALS: self._eq,
			ConditionOperator.NOT_EQUALS: self._neq,
			ConditionOperator.GREATER_THAN: self._gt,
			ConditionOperator.GREATER_EQUAL: self._gte,
			ConditionOperator.LESS_THAN: self._lt,
			ConditionOperator.LESS_EQUAL: self._lte,
			ConditionOperator.IN: self._in,
			ConditionOperator.NOT_IN: self._not_in,
			ConditionOperator.CONTAINS: self._contains,
			ConditionOperator.NOT_CONTAINS: self._not_contains,
			ConditionOperator.STARTS_WITH: self._starts_with,
			ConditionOperator.ENDS_WITH: self._ends_with,
			ConditionOperator.MATCHES: self._matches,
			ConditionOperator.EXISTS: self._exists,
			ConditionOperator.NOT_EXISTS: self._not_exists,
			ConditionOperator.BETWEEN: self._between,
			ConditionOperator.ANY_OF: self._any_of,
			ConditionOperator.ALL_OF: self._all_of,
			ConditionOperator.NONE_OF: self._none_of,
			ConditionOperator.IP_IN_RANGE: self._ip_in_range,
			ConditionOperator.TIME_BETWEEN: self._time_between,
		}

	def evaluate_conditions(
		self,
		conditions: dict[str, Any] | None,
		attributes: dict[str, Any],
	) -> bool:
		"""
		Evaluate a set of conditions against attributes.

		Condition format:
		{
			"attribute_name": {"operator": "value"},
			"roles": {"any_of": ["admin", "manager"]},
			"clearance_level": {"gte": 3},
			"_logic": "and"  # or "or", default is "and"
		}
		"""
		if not conditions:
			return True

		logic = conditions.pop('_logic', 'and').lower()
		results = []

		for attr_name, condition in conditions.items():
			if attr_name.startswith('_'):
				continue

			attr_value = self._get_nested_value(attributes, attr_name)
			result = self._evaluate_single(attr_value, condition)
			results.append(result)

		if logic == 'or':
			return any(results) if results else True
		else:  # and
			return all(results) if results else True

	def evaluate_subject(
		self,
		conditions: dict[str, Any] | None,
		subject: SubjectAttributes,
	) -> bool:
		"""Evaluate conditions against subject attributes."""
		return self.evaluate_conditions(conditions, subject.model_dump())

	def evaluate_resource(
		self,
		conditions: dict[str, Any] | None,
		resource: ResourceAttributes,
	) -> bool:
		"""Evaluate conditions against resource attributes."""
		return self.evaluate_conditions(conditions, resource.model_dump())

	def evaluate_environment(
		self,
		conditions: dict[str, Any] | None,
		environment: EnvironmentAttributes,
	) -> bool:
		"""Evaluate conditions against environment attributes."""
		return self.evaluate_conditions(conditions, environment.model_dump())

	def evaluate_action(
		self,
		conditions: dict[str, Any] | None,
		action: str,
	) -> bool:
		"""Evaluate conditions against action."""
		if not conditions:
			return True
		return self.evaluate_conditions(conditions, {'action': action})

	def _evaluate_single(
		self,
		attr_value: Any,
		condition: dict[str, Any] | Any,
	) -> bool:
		"""Evaluate a single condition."""
		# Simple equality if condition is not a dict
		if not isinstance(condition, dict):
			return attr_value == condition

		# Process each operator
		for operator, expected in condition.items():
			op_func = self._operators.get(operator)
			if not op_func:
				logger.warning(f"Unknown operator: {operator}")
				return False

			if not op_func(attr_value, expected):
				return False

		return True

	def _get_nested_value(self, data: dict, path: str) -> Any:
		"""Get nested value using dot notation."""
		keys = path.split('.')
		value = data
		for key in keys:
			if isinstance(value, dict):
				value = value.get(key)
			else:
				return None
		return value

	# Operator implementations

	def _eq(self, value: Any, expected: Any) -> bool:
		return value == expected

	def _neq(self, value: Any, expected: Any) -> bool:
		return value != expected

	def _gt(self, value: Any, expected: Any) -> bool:
		if value is None:
			return False
		return value > expected

	def _gte(self, value: Any, expected: Any) -> bool:
		if value is None:
			return False
		return value >= expected

	def _lt(self, value: Any, expected: Any) -> bool:
		if value is None:
			return False
		return value < expected

	def _lte(self, value: Any, expected: Any) -> bool:
		if value is None:
			return False
		return value <= expected

	def _in(self, value: Any, expected: list) -> bool:
		return value in expected

	def _not_in(self, value: Any, expected: list) -> bool:
		return value not in expected

	def _contains(self, value: Any, expected: Any) -> bool:
		if isinstance(value, str):
			return expected in value
		if isinstance(value, (list, set)):
			return expected in value
		return False

	def _not_contains(self, value: Any, expected: Any) -> bool:
		return not self._contains(value, expected)

	def _starts_with(self, value: Any, expected: str) -> bool:
		if not isinstance(value, str):
			return False
		return value.startswith(expected)

	def _ends_with(self, value: Any, expected: str) -> bool:
		if not isinstance(value, str):
			return False
		return value.endswith(expected)

	def _matches(self, value: Any, pattern: str) -> bool:
		if not isinstance(value, str):
			return False
		try:
			return bool(re.match(pattern, value))
		except re.error:
			logger.error(f"Invalid regex pattern: {pattern}")
			return False

	def _exists(self, value: Any, expected: bool) -> bool:
		exists = value is not None
		return exists == expected

	def _not_exists(self, value: Any, expected: bool) -> bool:
		return (value is None) == expected

	def _between(self, value: Any, expected: list) -> bool:
		if value is None or len(expected) != 2:
			return False
		return expected[0] <= value <= expected[1]

	def _any_of(self, value: Any, expected: list) -> bool:
		"""Check if any item in value is in expected."""
		if not isinstance(value, (list, set)):
			return value in expected
		return bool(set(value) & set(expected))

	def _all_of(self, value: Any, expected: list) -> bool:
		"""Check if all items in expected are in value."""
		if not isinstance(value, (list, set)):
			return False
		return set(expected).issubset(set(value))

	def _none_of(self, value: Any, expected: list) -> bool:
		"""Check if no items in value are in expected."""
		if not isinstance(value, (list, set)):
			return value not in expected
		return not bool(set(value) & set(expected))

	def _ip_in_range(self, value: str | None, expected: str | list) -> bool:
		"""Check if IP address is in CIDR range(s)."""
		if not value:
			return False
		try:
			ip = ip_address(value)
			ranges = [expected] if isinstance(expected, str) else expected
			for cidr in ranges:
				if ip in ip_network(cidr, strict=False):
					return True
			return False
		except ValueError as e:
			logger.error(f"Invalid IP/CIDR: {e}")
			return False

	def _time_between(self, value: Any, expected: list) -> bool:
		"""Check if time is between two times (HH:MM format)."""
		if len(expected) != 2:
			return False

		try:
			if isinstance(value, datetime):
				current_time = value.time()
			elif isinstance(value, time):
				current_time = value
			else:
				return False

			start = time.fromisoformat(expected[0])
			end = time.fromisoformat(expected[1])

			if start <= end:
				return start <= current_time <= end
			else:  # Crosses midnight
				return current_time >= start or current_time <= end

		except ValueError as e:
			logger.error(f"Invalid time format: {e}")
			return False


# Singleton evaluator
_evaluator = ConditionEvaluator()


def get_condition_evaluator() -> ConditionEvaluator:
	"""Get the singleton condition evaluator."""
	return _evaluator
