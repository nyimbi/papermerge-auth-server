# (c) Copyright Datacraft, 2026
"""Policy language parser for human-readable policies."""
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PolicyCondition:
	"""Parsed policy condition."""
	attribute: str
	operator: str
	value: Any
	negated: bool = False


@dataclass
class ParsedPolicy:
	"""Complete parsed policy structure."""
	effect: str = 'deny'
	target_resource_types: list[str] = field(default_factory=list)
	target_actions: list[str] = field(default_factory=list)
	subject_conditions: list[PolicyCondition] = field(default_factory=list)
	resource_conditions: list[PolicyCondition] = field(default_factory=list)
	environment_conditions: list[PolicyCondition] = field(default_factory=list)
	obligations: list[dict] = field(default_factory=list)
	raw_text: str = ''


class PolicyParser:
	"""
	Parser for human-readable policy language.

	Policy format:
	```
	ALLOW/DENY action ON resource_type
	WHEN subject.attr operator value
	AND resource.attr operator value
	DURING time_condition
	REQUIRE obligation
	```

	Example:
	```
	ALLOW read, write ON document
	WHEN subject.department = "Engineering"
	AND subject.clearance_level >= 3
	AND resource.classification IN ["internal", "public"]
	DURING business_hours
	REQUIRE log_access
	```
	"""

	# Keywords
	KEYWORDS = {
		'ALLOW', 'DENY', 'ON', 'WHEN', 'AND', 'OR', 'NOT',
		'DURING', 'REQUIRE', 'IF', 'UNLESS', 'FOR'
	}

	# Operators
	OPERATORS = {
		'=': 'eq',
		'==': 'eq',
		'!=': 'neq',
		'<>': 'neq',
		'>': 'gt',
		'>=': 'gte',
		'<': 'lt',
		'<=': 'lte',
		'IN': 'in',
		'NOT IN': 'not_in',
		'CONTAINS': 'contains',
		'NOT CONTAINS': 'not_contains',
		'STARTS WITH': 'starts_with',
		'ENDS WITH': 'ends_with',
		'MATCHES': 'matches',
		'IS': 'eq',
		'IS NOT': 'neq',
		'ANY OF': 'any_of',
		'ALL OF': 'all_of',
		'NONE OF': 'none_of',
	}

	def __init__(self):
		self._operator_pattern = '|'.join(
			re.escape(op) for op in sorted(self.OPERATORS.keys(), key=len, reverse=True)
		)

	def parse(self, policy_text: str) -> ParsedPolicy:
		"""Parse policy text into structured format."""
		result = ParsedPolicy(raw_text=policy_text)

		# Normalize text
		text = self._normalize(policy_text)
		lines = [l.strip() for l in text.split('\n') if l.strip()]

		for line in lines:
			self._parse_line(line, result)

		return result

	def _normalize(self, text: str) -> str:
		"""Normalize policy text."""
		# Remove comments
		text = re.sub(r'#.*$', '', text, flags=re.MULTILINE)
		text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)

		# Normalize whitespace
		text = re.sub(r'\s+', ' ', text)

		# Handle line continuations
		text = re.sub(r'\\\s*\n', ' ', text)

		return text.strip()

	def _parse_line(self, line: str, result: ParsedPolicy):
		"""Parse a single policy line."""
		upper = line.upper()

		# Effect and target
		if upper.startswith('ALLOW') or upper.startswith('DENY'):
			self._parse_effect_line(line, result)

		# Conditions
		elif upper.startswith('WHEN') or upper.startswith('AND') or upper.startswith('IF'):
			self._parse_condition_line(line, result)

		# Time constraints
		elif upper.startswith('DURING'):
			self._parse_during_line(line, result)

		# Obligations
		elif upper.startswith('REQUIRE'):
			self._parse_require_line(line, result)

	def _parse_effect_line(self, line: str, result: ParsedPolicy):
		"""Parse effect line: ALLOW/DENY actions ON resource_types."""
		upper = line.upper()

		# Extract effect
		if upper.startswith('ALLOW'):
			result.effect = 'allow'
			line = line[5:].strip()
		elif upper.startswith('DENY'):
			result.effect = 'deny'
			line = line[4:].strip()

		# Split at ON
		parts = re.split(r'\s+ON\s+', line, flags=re.IGNORECASE)
		if len(parts) >= 2:
			actions_part = parts[0]
			resources_part = parts[1]

			# Parse actions
			actions = [a.strip().lower() for a in actions_part.split(',')]
			result.target_actions.extend(actions)

			# Parse resource types
			resources = [r.strip().lower() for r in resources_part.split(',')]
			result.target_resource_types.extend(resources)
		elif parts:
			# Only actions specified
			actions = [a.strip().lower() for a in parts[0].split(',')]
			result.target_actions.extend(actions)

	def _parse_condition_line(self, line: str, result: ParsedPolicy):
		"""Parse condition line: WHEN/AND subject.attr op value."""
		# Remove leading keyword
		line = re.sub(r'^(WHEN|AND|IF)\s+', '', line, flags=re.IGNORECASE).strip()

		# Parse condition
		condition = self._parse_condition(line)
		if not condition:
			return

		# Determine condition type by prefix
		attr_lower = condition.attribute.lower()
		if attr_lower.startswith('subject.'):
			condition.attribute = attr_lower[8:]
			result.subject_conditions.append(condition)
		elif attr_lower.startswith('resource.'):
			condition.attribute = attr_lower[9:]
			result.resource_conditions.append(condition)
		elif attr_lower.startswith('environment.') or attr_lower.startswith('env.'):
			prefix_len = 12 if attr_lower.startswith('environment.') else 4
			condition.attribute = attr_lower[prefix_len:]
			result.environment_conditions.append(condition)
		else:
			# Default to subject condition
			result.subject_conditions.append(condition)

	def _parse_condition(self, expr: str) -> PolicyCondition | None:
		"""Parse a single condition expression."""
		# Check for negation
		negated = False
		if expr.upper().startswith('NOT '):
			negated = True
			expr = expr[4:].strip()

		# Find operator
		for op_text, op_code in sorted(
			self.OPERATORS.items(), key=lambda x: len(x[0]), reverse=True
		):
			pattern = rf'\s+{re.escape(op_text)}\s+'
			match = re.search(pattern, expr, flags=re.IGNORECASE)
			if match:
				attr = expr[:match.start()].strip()
				value_str = expr[match.end():].strip()
				value = self._parse_value(value_str)

				return PolicyCondition(
					attribute=attr,
					operator=op_code,
					value=value,
					negated=negated,
				)

		# Try simple equality with =
		if '=' in expr and '!=' not in expr and '>=' not in expr and '<=' not in expr:
			parts = expr.split('=', 1)
			if len(parts) == 2:
				return PolicyCondition(
					attribute=parts[0].strip(),
					operator='eq',
					value=self._parse_value(parts[1].strip()),
					negated=negated,
				)

		logger.warning(f"Could not parse condition: {expr}")
		return None

	def _parse_value(self, value_str: str) -> Any:
		"""Parse a value from string."""
		value_str = value_str.strip()

		# List
		if value_str.startswith('[') and value_str.endswith(']'):
			inner = value_str[1:-1]
			items = [self._parse_value(v.strip()) for v in inner.split(',')]
			return items

		# String (quoted)
		if (value_str.startswith('"') and value_str.endswith('"')) or \
		   (value_str.startswith("'") and value_str.endswith("'")):
			return value_str[1:-1]

		# Boolean
		if value_str.lower() == 'true':
			return True
		if value_str.lower() == 'false':
			return False

		# None/null
		if value_str.lower() in ('null', 'none'):
			return None

		# Number
		try:
			if '.' in value_str:
				return float(value_str)
			return int(value_str)
		except ValueError:
			pass

		# Default to string
		return value_str

	def _parse_during_line(self, line: str, result: ParsedPolicy):
		"""Parse time constraint: DURING business_hours / time_range."""
		line = re.sub(r'^DURING\s+', '', line, flags=re.IGNORECASE).strip()

		# Predefined time periods
		if line.lower() == 'business_hours':
			result.environment_conditions.append(PolicyCondition(
				attribute='is_business_hours',
				operator='eq',
				value=True,
			))
		elif line.lower() == 'after_hours':
			result.environment_conditions.append(PolicyCondition(
				attribute='is_business_hours',
				operator='eq',
				value=False,
			))
		else:
			# Try to parse time range: HH:MM - HH:MM
			match = re.match(r'(\d{2}:\d{2})\s*-\s*(\d{2}:\d{2})', line)
			if match:
				result.environment_conditions.append(PolicyCondition(
					attribute='current_time',
					operator='time_between',
					value=[match.group(1), match.group(2)],
				))

	def _parse_require_line(self, line: str, result: ParsedPolicy):
		"""Parse obligation: REQUIRE log_access, notify_admin."""
		line = re.sub(r'^REQUIRE\s+', '', line, flags=re.IGNORECASE).strip()

		obligations = [o.strip() for o in line.split(',')]
		for obl in obligations:
			result.obligations.append({
				'type': obl.lower(),
				'params': {},
			})

	def to_dict(self, parsed: ParsedPolicy) -> dict:
		"""Convert parsed policy to dictionary for storage."""
		def condition_to_dict(c: PolicyCondition) -> dict:
			d = {c.attribute: {c.operator: c.value}}
			if c.negated:
				d['_negated'] = True
			return d

		subject_conds = {}
		for c in parsed.subject_conditions:
			subject_conds[c.attribute] = {c.operator: c.value}

		resource_conds = {}
		for c in parsed.resource_conditions:
			resource_conds[c.attribute] = {c.operator: c.value}

		env_conds = {}
		for c in parsed.environment_conditions:
			env_conds[c.attribute] = {c.operator: c.value}

		return {
			'effect': parsed.effect,
			'target_resource_types': parsed.target_resource_types,
			'target_actions': parsed.target_actions,
			'subject_conditions': subject_conds or None,
			'resource_conditions': resource_conds or None,
			'environment_conditions': env_conds or None,
			'obligations': parsed.obligations or None,
		}


# Example policies
EXAMPLE_POLICIES = {
	'department_access': """
		ALLOW read, write ON document
		WHEN subject.department = "Engineering"
		AND resource.department = "Engineering"
	""",

	'confidential_access': """
		ALLOW read ON document
		WHEN subject.clearance_level >= 3
		AND resource.classification IN ["confidential", "secret"]
		DURING business_hours
		REQUIRE log_access
	""",

	'owner_full_access': """
		ALLOW read, write, delete, share ON document
		WHEN subject.user_id = resource.owner_id
	""",

	'deny_external': """
		DENY read, write, download ON document
		WHEN NOT environment.is_internal_network
		AND resource.classification = "internal"
	""",
}
