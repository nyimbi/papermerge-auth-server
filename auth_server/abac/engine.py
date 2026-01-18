# (c) Copyright Datacraft, 2026
"""ABAC Policy Evaluation Engine."""
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
	ABACPolicy, ABACRule, ABACEvaluationLog, ABACRequest,
	PolicyEffect, CombiningAlgorithm
)
from .conditions import ConditionEvaluator, get_condition_evaluator

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
	"""Result of evaluating a single rule."""
	rule_id: UUID
	rule_name: str
	matched: bool
	effect: PolicyEffect
	obligations: dict | None = None


@dataclass
class PolicyResult:
	"""Result of evaluating a single policy."""
	policy_id: UUID
	policy_name: str
	applicable: bool
	effect: PolicyEffect | None
	rule_results: list[RuleResult] = field(default_factory=list)


@dataclass
class ABACDecision:
	"""Final ABAC authorization decision."""
	allowed: bool
	effect: PolicyEffect
	policy_results: list[PolicyResult] = field(default_factory=list)
	obligations: list[dict] = field(default_factory=list)
	evaluation_time_ms: float = 0
	reason: str | None = None


class ABACEngine:
	"""
	Attribute-Based Access Control Engine.

	Evaluates policies against request context using XACML-like semantics.
	"""

	def __init__(
		self,
		db: Session,
		evaluator: ConditionEvaluator | None = None,
		enable_logging: bool = True,
	):
		self.db = db
		self.evaluator = evaluator or get_condition_evaluator()
		self.enable_logging = enable_logging

	async def evaluate(self, request: ABACRequest) -> ABACDecision:
		"""
		Evaluate an ABAC authorization request.

		Args:
			request: The authorization request with subject, resource, action, environment

		Returns:
			ABACDecision with the final authorization result
		"""
		start_time = time.time()

		# Get active policies ordered by priority
		policies = await self._get_applicable_policies(request)

		if not policies:
			# No applicable policies - default deny
			decision = ABACDecision(
				allowed=False,
				effect=PolicyEffect.DENY,
				reason="No applicable policies",
				evaluation_time_ms=(time.time() - start_time) * 1000,
			)
			await self._log_evaluation(request, decision)
			return decision

		# Evaluate each policy
		policy_results: list[PolicyResult] = []
		all_obligations: list[dict] = []

		for policy in policies:
			result = await self._evaluate_policy(policy, request)
			policy_results.append(result)

			if result.applicable and result.effect:
				for rule_result in result.rule_results:
					if rule_result.matched and rule_result.obligations:
						all_obligations.append(rule_result.obligations)

		# Combine results using configured algorithm
		final_effect = self._combine_results(policies[0], policy_results)

		decision = ABACDecision(
			allowed=final_effect == PolicyEffect.ALLOW,
			effect=final_effect,
			policy_results=policy_results,
			obligations=all_obligations,
			evaluation_time_ms=(time.time() - start_time) * 1000,
		)

		await self._log_evaluation(request, decision)

		return decision

	async def evaluate_simple(
		self,
		user_id: UUID,
		resource_id: UUID,
		resource_type: str,
		action: str,
		**context,
	) -> bool:
		"""
		Simplified evaluation interface.

		Args:
			user_id: User making the request
			resource_id: Resource being accessed
			resource_type: Type of resource
			action: Action being performed
			**context: Additional context attributes

		Returns:
			True if access is allowed
		"""
		from datetime import datetime, timezone
		from .models import (
			SubjectAttributes, ResourceAttributes, EnvironmentAttributes, ActionType
		)

		# Build request from parameters
		subject = SubjectAttributes(
			user_id=user_id,
			**context.get('subject', {})
		)

		resource = ResourceAttributes(
			resource_id=resource_id,
			resource_type=resource_type,
			**context.get('resource', {})
		)

		environment = EnvironmentAttributes(
			current_time=datetime.now(timezone.utc),
			**context.get('environment', {})
		)

		try:
			action_type = ActionType(action)
		except ValueError:
			logger.warning(f"Unknown action type: {action}, defaulting to READ")
			action_type = ActionType.READ

		request = ABACRequest(
			subject=subject,
			resource=resource,
			action=action_type,
			environment=environment,
		)

		decision = await self.evaluate(request)
		return decision.allowed

	async def _get_applicable_policies(
		self,
		request: ABACRequest,
	) -> list[ABACPolicy]:
		"""Get policies that may apply to this request."""
		stmt = (
			select(ABACPolicy)
			.where(ABACPolicy.is_active == True)
			.order_by(ABACPolicy.priority)
		)
		policies = list(self.db.scalars(stmt))

		# Filter by target conditions
		applicable = []
		for policy in policies:
			if self._matches_target(policy, request):
				applicable.append(policy)

		return applicable

	def _matches_target(self, policy: ABACPolicy, request: ABACRequest) -> bool:
		"""Check if request matches policy target conditions."""
		if not policy.target_conditions:
			return True

		# Target can specify resource types, actions, etc.
		target = policy.target_conditions

		# Check resource type
		if 'resource_types' in target:
			if request.resource.resource_type not in target['resource_types']:
				return False

		# Check actions
		if 'actions' in target:
			if request.action.value not in target['actions']:
				return False

		# Check document types
		if 'document_types' in target:
			if request.resource.document_type not in target['document_types']:
				return False

		return True

	async def _evaluate_policy(
		self,
		policy: ABACPolicy,
		request: ABACRequest,
	) -> PolicyResult:
		"""Evaluate a single policy."""
		rule_results: list[RuleResult] = []
		applicable = False
		final_effect: PolicyEffect | None = None

		for rule in policy.rules:
			if not rule.is_active:
				continue

			result = await self._evaluate_rule(rule, request)
			rule_results.append(result)

			if result.matched:
				applicable = True
				effect = PolicyEffect(rule.effect)

				# Apply combining algorithm
				algorithm = CombiningAlgorithm(policy.combining_algorithm)

				if algorithm == CombiningAlgorithm.DENY_OVERRIDES:
					if effect == PolicyEffect.DENY:
						final_effect = PolicyEffect.DENY
						break
					elif final_effect is None:
						final_effect = effect

				elif algorithm == CombiningAlgorithm.PERMIT_OVERRIDES:
					if effect == PolicyEffect.ALLOW:
						final_effect = PolicyEffect.ALLOW
						break
					elif final_effect is None:
						final_effect = effect

				elif algorithm == CombiningAlgorithm.FIRST_APPLICABLE:
					final_effect = effect
					break

				elif algorithm == CombiningAlgorithm.ONLY_ONE_APPLICABLE:
					if final_effect is not None:
						# Multiple applicable - indeterminate
						final_effect = PolicyEffect.DENY
						break
					final_effect = effect

		return PolicyResult(
			policy_id=policy.id,
			policy_name=policy.name,
			applicable=applicable,
			effect=final_effect,
			rule_results=rule_results,
		)

	async def _evaluate_rule(
		self,
		rule: ABACRule,
		request: ABACRequest,
	) -> RuleResult:
		"""Evaluate a single rule."""
		# All conditions must match for rule to apply
		subject_match = self.evaluator.evaluate_subject(
			rule.subject_conditions.copy() if rule.subject_conditions else None,
			request.subject,
		)
		if not subject_match:
			return RuleResult(
				rule_id=rule.id,
				rule_name=rule.name,
				matched=False,
				effect=PolicyEffect(rule.effect),
			)

		resource_match = self.evaluator.evaluate_resource(
			rule.resource_conditions.copy() if rule.resource_conditions else None,
			request.resource,
		)
		if not resource_match:
			return RuleResult(
				rule_id=rule.id,
				rule_name=rule.name,
				matched=False,
				effect=PolicyEffect(rule.effect),
			)

		action_match = self.evaluator.evaluate_action(
			rule.action_conditions.copy() if rule.action_conditions else None,
			request.action.value,
		)
		if not action_match:
			return RuleResult(
				rule_id=rule.id,
				rule_name=rule.name,
				matched=False,
				effect=PolicyEffect(rule.effect),
			)

		environment_match = self.evaluator.evaluate_environment(
			rule.environment_conditions.copy() if rule.environment_conditions else None,
			request.environment,
		)
		if not environment_match:
			return RuleResult(
				rule_id=rule.id,
				rule_name=rule.name,
				matched=False,
				effect=PolicyEffect(rule.effect),
			)

		return RuleResult(
			rule_id=rule.id,
			rule_name=rule.name,
			matched=True,
			effect=PolicyEffect(rule.effect),
			obligations=rule.obligations,
		)

	def _combine_results(
		self,
		policy: ABACPolicy,
		results: list[PolicyResult],
	) -> PolicyEffect:
		"""Combine policy results into final decision."""
		algorithm = CombiningAlgorithm(policy.combining_algorithm)

		for result in results:
			if not result.applicable:
				continue

			if algorithm == CombiningAlgorithm.DENY_OVERRIDES:
				if result.effect == PolicyEffect.DENY:
					return PolicyEffect.DENY

			elif algorithm == CombiningAlgorithm.PERMIT_OVERRIDES:
				if result.effect == PolicyEffect.ALLOW:
					return PolicyEffect.ALLOW

			elif algorithm == CombiningAlgorithm.FIRST_APPLICABLE:
				if result.effect:
					return result.effect

		# Default based on algorithm
		if algorithm == CombiningAlgorithm.DENY_OVERRIDES:
			# If no deny, allow if any permit
			for result in results:
				if result.applicable and result.effect == PolicyEffect.ALLOW:
					return PolicyEffect.ALLOW
			return PolicyEffect.DENY

		elif algorithm == CombiningAlgorithm.PERMIT_OVERRIDES:
			# If no permit, deny
			return PolicyEffect.DENY

		return PolicyEffect.DENY

	async def _log_evaluation(
		self,
		request: ABACRequest,
		decision: ABACDecision,
	) -> None:
		"""Log the evaluation for audit purposes."""
		if not self.enable_logging:
			return

		log_entry = ABACEvaluationLog(
			request_context={
				'subject': request.subject.model_dump(mode='json'),
				'resource': request.resource.model_dump(mode='json'),
				'action': request.action.value,
				'environment': request.environment.model_dump(mode='json'),
			},
			decision=decision.effect.value,
			matched_policies=[
				{
					'id': str(r.policy_id),
					'name': r.policy_name,
					'effect': r.effect.value if r.effect else None,
				}
				for r in decision.policy_results
				if r.applicable
			],
			matched_rules=[
				{
					'id': str(rr.rule_id),
					'name': rr.rule_name,
					'effect': rr.effect.value,
				}
				for pr in decision.policy_results
				for rr in pr.rule_results
				if rr.matched
			],
			evaluation_time_ms=decision.evaluation_time_ms,
			obligations_executed=decision.obligations,
		)

		self.db.add(log_entry)
		self.db.commit()

	# Policy management methods

	async def create_policy(
		self,
		name: str,
		description: str | None = None,
		priority: int = 100,
		combining_algorithm: str = 'deny_overrides',
		target_conditions: dict | None = None,
		created_by: UUID | None = None,
	) -> ABACPolicy:
		"""Create a new ABAC policy."""
		policy = ABACPolicy(
			name=name,
			description=description,
			priority=priority,
			combining_algorithm=combining_algorithm,
			target_conditions=target_conditions,
			created_by=created_by,
		)
		self.db.add(policy)
		self.db.commit()
		self.db.refresh(policy)
		return policy

	async def add_rule(
		self,
		policy_id: UUID,
		name: str,
		effect: str = 'deny',
		priority: int = 100,
		subject_conditions: dict | None = None,
		resource_conditions: dict | None = None,
		action_conditions: dict | None = None,
		environment_conditions: dict | None = None,
		obligations: dict | None = None,
		description: str | None = None,
	) -> ABACRule:
		"""Add a rule to a policy."""
		rule = ABACRule(
			policy_id=policy_id,
			name=name,
			effect=effect,
			priority=priority,
			subject_conditions=subject_conditions,
			resource_conditions=resource_conditions,
			action_conditions=action_conditions,
			environment_conditions=environment_conditions,
			obligations=obligations,
			description=description,
		)
		self.db.add(rule)
		self.db.commit()
		self.db.refresh(rule)
		return rule

	async def get_policy(self, policy_id: UUID) -> ABACPolicy | None:
		"""Get a policy by ID."""
		return self.db.get(ABACPolicy, policy_id)

	async def list_policies(
		self,
		active_only: bool = True,
	) -> list[ABACPolicy]:
		"""List all policies."""
		stmt = select(ABACPolicy).order_by(ABACPolicy.priority)
		if active_only:
			stmt = stmt.where(ABACPolicy.is_active == True)
		return list(self.db.scalars(stmt))
