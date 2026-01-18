# (c) Copyright Datacraft, 2026
"""PBAC Policy Evaluation Engine."""
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from auth_server.abac.conditions import ConditionEvaluator, get_condition_evaluator
from .models import (
	Policy, PolicySet, PolicyVersion, PolicyEvaluationLog,
	PolicyStatus, PolicyEffect
)
from .parser import PolicyParser

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
	"""Result of PBAC policy evaluation."""
	allowed: bool
	effect: str
	matched_policy_id: UUID | None = None
	matched_policy_name: str | None = None
	matched_policy_version: int | None = None
	obligations: list[dict] = field(default_factory=list)
	evaluation_time_ms: float = 0
	reason: str | None = None


@dataclass
class EvaluationContext:
	"""Context for policy evaluation."""
	subject: dict[str, Any]
	resource: dict[str, Any]
	action: str
	environment: dict[str, Any]


class PBACEngine:
	"""
	Policy-Based Access Control Engine.

	Evaluates policies with versioning support and approval workflows.
	"""

	def __init__(
		self,
		db: Session,
		evaluator: ConditionEvaluator | None = None,
		enable_logging: bool = True,
	):
		self.db = db
		self.evaluator = evaluator or get_condition_evaluator()
		self.parser = PolicyParser()
		self.enable_logging = enable_logging

	async def evaluate(
		self,
		subject: dict[str, Any],
		resource: dict[str, Any],
		action: str,
		environment: dict[str, Any] | None = None,
	) -> PolicyDecision:
		"""
		Evaluate access request against active policies.

		Args:
			subject: Subject/user attributes
			resource: Resource attributes
			action: Action being performed
			environment: Environmental context

		Returns:
			PolicyDecision with authorization result
		"""
		start_time = time.time()

		if environment is None:
			environment = {
				'current_time': datetime.now(timezone.utc),
				'is_business_hours': self._is_business_hours(),
			}

		context = EvaluationContext(
			subject=subject,
			resource=resource,
			action=action,
			environment=environment,
		)

		# Get applicable policies
		policies = await self._get_applicable_policies(context)

		if not policies:
			decision = PolicyDecision(
				allowed=False,
				effect='deny',
				reason="No applicable policies",
				evaluation_time_ms=(time.time() - start_time) * 1000,
			)
			await self._log_evaluation(context, decision)
			return decision

		# Evaluate policies (deny overrides by default)
		allow_policies = []
		deny_policies = []

		for policy in policies:
			if self._evaluate_policy(policy, context):
				if policy.effect == PolicyEffect.DENY.value:
					deny_policies.append(policy)
				else:
					allow_policies.append(policy)

		# Deny overrides
		if deny_policies:
			policy = deny_policies[0]
			decision = PolicyDecision(
				allowed=False,
				effect='deny',
				matched_policy_id=policy.id,
				matched_policy_name=policy.name,
				matched_policy_version=policy.current_version,
				obligations=policy.obligations or [],
				evaluation_time_ms=(time.time() - start_time) * 1000,
			)
		elif allow_policies:
			policy = allow_policies[0]
			decision = PolicyDecision(
				allowed=True,
				effect='allow',
				matched_policy_id=policy.id,
				matched_policy_name=policy.name,
				matched_policy_version=policy.current_version,
				obligations=policy.obligations or [],
				evaluation_time_ms=(time.time() - start_time) * 1000,
			)
		else:
			decision = PolicyDecision(
				allowed=False,
				effect='deny',
				reason="No matching policies",
				evaluation_time_ms=(time.time() - start_time) * 1000,
			)

		await self._log_evaluation(context, decision)
		return decision

	async def _get_applicable_policies(
		self,
		context: EvaluationContext,
	) -> list[Policy]:
		"""Get policies that may apply to this request."""
		now = datetime.now(timezone.utc)

		stmt = (
			select(Policy)
			.where(Policy.status == PolicyStatus.ACTIVE.value)
			.order_by(Policy.priority)
		)

		policies = list(self.db.scalars(stmt))

		# Filter by target and temporal constraints
		applicable = []
		for policy in policies:
			# Check temporal constraints
			if policy.effective_from and policy.effective_from > now:
				continue
			if policy.effective_until and policy.effective_until < now:
				continue

			# Check resource type target
			if policy.target_resource_types:
				resource_type = context.resource.get('resource_type')
				if resource_type not in policy.target_resource_types:
					continue

			# Check action target
			if policy.target_actions:
				if context.action not in policy.target_actions:
					continue

			applicable.append(policy)

		return applicable

	def _evaluate_policy(
		self,
		policy: Policy,
		context: EvaluationContext,
	) -> bool:
		"""Check if policy conditions match the context."""
		# Evaluate subject conditions
		if policy.subject_conditions:
			if not self.evaluator.evaluate_conditions(
				policy.subject_conditions.copy(),
				context.subject
			):
				return False

		# Evaluate resource conditions
		if policy.resource_conditions:
			if not self.evaluator.evaluate_conditions(
				policy.resource_conditions.copy(),
				context.resource
			):
				return False

		# Evaluate environment conditions
		if policy.environment_conditions:
			if not self.evaluator.evaluate_conditions(
				policy.environment_conditions.copy(),
				context.environment
			):
				return False

		return True

	def _is_business_hours(self) -> bool:
		"""Check if current time is within business hours."""
		now = datetime.now()
		# Monday = 0, Sunday = 6
		if now.weekday() >= 5:
			return False
		hour = now.hour
		return 9 <= hour < 18

	async def _log_evaluation(
		self,
		context: EvaluationContext,
		decision: PolicyDecision,
	) -> None:
		"""Log evaluation for audit."""
		if not self.enable_logging:
			return

		log_entry = PolicyEvaluationLog(
			request_context={
				'subject': context.subject,
				'resource': context.resource,
				'action': context.action,
				'environment': context.environment,
			},
			decision=decision.effect,
			matched_policy_id=decision.matched_policy_id,
			matched_policy_name=decision.matched_policy_name,
			matched_policy_version=decision.matched_policy_version,
			evaluation_time_ms=decision.evaluation_time_ms,
			obligations_executed=decision.obligations,
		)

		self.db.add(log_entry)
		self.db.commit()

	# Policy management

	async def create_policy(
		self,
		name: str,
		effect: str = 'deny',
		policy_text: str | None = None,
		description: str | None = None,
		priority: int = 100,
		target_resource_types: list[str] | None = None,
		target_actions: list[str] | None = None,
		subject_conditions: dict | None = None,
		resource_conditions: dict | None = None,
		environment_conditions: dict | None = None,
		obligations: dict | None = None,
		policy_set_id: UUID | None = None,
		created_by: UUID | None = None,
	) -> Policy:
		"""Create a new policy."""
		# Parse policy text if provided
		if policy_text:
			parsed = self.parser.parse(policy_text)
			parsed_dict = self.parser.to_dict(parsed)

			effect = parsed_dict.get('effect', effect)
			target_resource_types = parsed_dict.get('target_resource_types') or target_resource_types
			target_actions = parsed_dict.get('target_actions') or target_actions
			subject_conditions = parsed_dict.get('subject_conditions') or subject_conditions
			resource_conditions = parsed_dict.get('resource_conditions') or resource_conditions
			environment_conditions = parsed_dict.get('environment_conditions') or environment_conditions
			obligations = parsed_dict.get('obligations') or obligations

		policy = Policy(
			name=name,
			description=description,
			effect=effect,
			priority=priority,
			policy_text=policy_text,
			target_resource_types=target_resource_types,
			target_actions=target_actions,
			subject_conditions=subject_conditions,
			resource_conditions=resource_conditions,
			environment_conditions=environment_conditions,
			obligations=obligations,
			policy_set_id=policy_set_id,
			created_by=created_by,
			status=PolicyStatus.DRAFT.value,
		)

		self.db.add(policy)
		self.db.commit()
		self.db.refresh(policy)

		# Create initial version
		await self._create_version(policy, "Initial creation", created_by)

		return policy

	async def update_policy(
		self,
		policy_id: UUID,
		change_summary: str,
		updated_by: UUID | None = None,
		**updates,
	) -> Policy:
		"""Update a policy and create new version."""
		policy = self.db.get(Policy, policy_id)
		if not policy:
			raise ValueError(f"Policy not found: {policy_id}")

		# Store previous status
		prev_status = policy.status

		# Apply updates
		for key, value in updates.items():
			if hasattr(policy, key):
				setattr(policy, key, value)

		# Parse policy text if updated
		if 'policy_text' in updates and updates['policy_text']:
			parsed = self.parser.parse(updates['policy_text'])
			parsed_dict = self.parser.to_dict(parsed)

			policy.effect = parsed_dict.get('effect', policy.effect)
			policy.target_resource_types = parsed_dict.get('target_resource_types')
			policy.target_actions = parsed_dict.get('target_actions')
			policy.subject_conditions = parsed_dict.get('subject_conditions')
			policy.resource_conditions = parsed_dict.get('resource_conditions')
			policy.environment_conditions = parsed_dict.get('environment_conditions')
			policy.obligations = parsed_dict.get('obligations')

		# Increment version
		policy.current_version += 1
		policy.status = PolicyStatus.DRAFT.value

		self.db.commit()
		self.db.refresh(policy)

		# Create version record
		await self._create_version(
			policy, change_summary, updated_by,
			previous_status=prev_status,
			change_type='update',
		)

		return policy

	async def activate_policy(
		self,
		policy_id: UUID,
		activated_by: UUID | None = None,
	) -> Policy:
		"""Activate a policy."""
		policy = self.db.get(Policy, policy_id)
		if not policy:
			raise ValueError(f"Policy not found: {policy_id}")

		prev_status = policy.status
		policy.status = PolicyStatus.ACTIVE.value
		policy.approved_by = activated_by
		policy.approved_at = datetime.now(timezone.utc)

		self.db.commit()

		await self._create_version(
			policy, "Policy activated", activated_by,
			previous_status=prev_status,
			change_type='activation',
		)

		return policy

	async def deprecate_policy(
		self,
		policy_id: UUID,
		deprecated_by: UUID | None = None,
	) -> Policy:
		"""Deprecate a policy."""
		policy = self.db.get(Policy, policy_id)
		if not policy:
			raise ValueError(f"Policy not found: {policy_id}")

		prev_status = policy.status
		policy.status = PolicyStatus.DEPRECATED.value

		self.db.commit()

		await self._create_version(
			policy, "Policy deprecated", deprecated_by,
			previous_status=prev_status,
			change_type='deprecation',
		)

		return policy

	async def rollback_policy(
		self,
		policy_id: UUID,
		target_version: int,
		rolled_back_by: UUID | None = None,
	) -> Policy:
		"""Rollback policy to a previous version."""
		policy = self.db.get(Policy, policy_id)
		if not policy:
			raise ValueError(f"Policy not found: {policy_id}")

		# Find target version
		stmt = select(PolicyVersion).where(
			PolicyVersion.policy_id == policy_id,
			PolicyVersion.version == target_version,
		)
		version = self.db.scalar(stmt)
		if not version:
			raise ValueError(f"Version not found: {target_version}")

		# Restore from snapshot
		snapshot = version.policy_snapshot
		prev_status = policy.status

		policy.effect = snapshot.get('effect', policy.effect)
		policy.target_resource_types = snapshot.get('target_resource_types')
		policy.target_actions = snapshot.get('target_actions')
		policy.subject_conditions = snapshot.get('subject_conditions')
		policy.resource_conditions = snapshot.get('resource_conditions')
		policy.environment_conditions = snapshot.get('environment_conditions')
		policy.obligations = snapshot.get('obligations')
		policy.policy_text = snapshot.get('policy_text')
		policy.current_version += 1
		policy.status = PolicyStatus.DRAFT.value

		self.db.commit()

		await self._create_version(
			policy, f"Rolled back to version {target_version}", rolled_back_by,
			previous_status=prev_status,
			change_type='rollback',
		)

		return policy

	async def get_policy_history(
		self,
		policy_id: UUID,
	) -> list[PolicyVersion]:
		"""Get version history for a policy."""
		stmt = (
			select(PolicyVersion)
			.where(PolicyVersion.policy_id == policy_id)
			.order_by(PolicyVersion.version.desc())
		)
		return list(self.db.scalars(stmt))

	async def _create_version(
		self,
		policy: Policy,
		change_summary: str,
		created_by: UUID | None = None,
		previous_status: str | None = None,
		change_type: str = 'update',
	) -> PolicyVersion:
		"""Create a version snapshot of a policy."""
		snapshot = {
			'effect': policy.effect,
			'target_resource_types': policy.target_resource_types,
			'target_actions': policy.target_actions,
			'subject_conditions': policy.subject_conditions,
			'resource_conditions': policy.resource_conditions,
			'environment_conditions': policy.environment_conditions,
			'obligations': policy.obligations,
			'policy_text': policy.policy_text,
			'description': policy.description,
			'priority': policy.priority,
		}

		version = PolicyVersion(
			policy_id=policy.id,
			version=policy.current_version,
			policy_snapshot=snapshot,
			change_summary=change_summary,
			change_type=change_type,
			previous_status=previous_status,
			new_status=policy.status,
			created_by=created_by,
		)

		self.db.add(version)
		self.db.commit()

		return version

	async def list_policies(
		self,
		status: str | None = None,
		policy_set_id: UUID | None = None,
	) -> list[Policy]:
		"""List policies with optional filters."""
		stmt = select(Policy).order_by(Policy.priority)

		if status:
			stmt = stmt.where(Policy.status == status)
		if policy_set_id:
			stmt = stmt.where(Policy.policy_set_id == policy_set_id)

		return list(self.db.scalars(stmt))

	async def get_policy(self, policy_id: UUID) -> Policy | None:
		"""Get a policy by ID."""
		return self.db.get(Policy, policy_id)
