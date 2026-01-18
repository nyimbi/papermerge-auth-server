# (c) Copyright Datacraft, 2026
"""Relationship graph traversal and permission checking."""
import logging
from dataclasses import dataclass, field
from typing import Any, Callable
from uuid import UUID

from sqlalchemy.orm import Session

from .tuples import RelationTuple, RelationshipStore, Relations

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
	"""Result of a permission check."""
	allowed: bool
	path: list[str] = field(default_factory=list)
	cached: bool = False
	evaluation_count: int = 0


@dataclass
class RelationDefinition:
	"""
	Definition of a relation with rewrite rules.

	Supports:
	- Direct relations: user has relation to object
	- Computed unions: permission = union of multiple relations
	- Computed intersections: permission requires all relations
	- Parent traversal: inherit from parent object
	"""
	name: str
	direct_users: bool = True  # Allow direct user assignment
	union: list[str] | None = None  # Union of other relations
	intersection: list[str] | None = None  # Intersection of relations
	inherit_from: str | None = None  # Inherit from parent via this relation
	inherit_relation: str | None = None  # The relation to inherit


class RelationshipGraph:
	"""
	Defines the relationship model for the authorization system.

	This is the schema/type definition, not the data.
	"""

	def __init__(self):
		self._definitions: dict[str, dict[str, RelationDefinition]] = {}

	def define_type(
		self,
		object_type: str,
		relations: dict[str, RelationDefinition],
	):
		"""Define relations for an object type."""
		self._definitions[object_type] = relations

	def get_definition(
		self,
		object_type: str,
		relation: str,
	) -> RelationDefinition | None:
		"""Get relation definition."""
		type_defs = self._definitions.get(object_type, {})
		return type_defs.get(relation)

	def get_type_relations(self, object_type: str) -> list[str]:
		"""Get all relations defined for a type."""
		return list(self._definitions.get(object_type, {}).keys())


def create_default_graph() -> RelationshipGraph:
	"""Create the default relationship graph for dArchiva."""
	graph = RelationshipGraph()

	# Document relations
	graph.define_type('document', {
		Relations.OWNER: RelationDefinition(
			name=Relations.OWNER,
			direct_users=True,
		),
		Relations.EDITOR: RelationDefinition(
			name=Relations.EDITOR,
			direct_users=True,
		),
		Relations.VIEWER: RelationDefinition(
			name=Relations.VIEWER,
			direct_users=True,
			union=[Relations.EDITOR, Relations.OWNER],
		),
		Relations.CAN_READ: RelationDefinition(
			name=Relations.CAN_READ,
			direct_users=False,
			union=[Relations.VIEWER, Relations.EDITOR, Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_READ,
		),
		Relations.CAN_WRITE: RelationDefinition(
			name=Relations.CAN_WRITE,
			direct_users=False,
			union=[Relations.EDITOR, Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_WRITE,
		),
		Relations.CAN_DELETE: RelationDefinition(
			name=Relations.CAN_DELETE,
			direct_users=False,
			union=[Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_DELETE,
		),
		Relations.CAN_SHARE: RelationDefinition(
			name=Relations.CAN_SHARE,
			direct_users=False,
			union=[Relations.OWNER],
		),
		'parent': RelationDefinition(
			name='parent',
			direct_users=False,
		),
	})

	# Folder relations
	graph.define_type('folder', {
		Relations.OWNER: RelationDefinition(
			name=Relations.OWNER,
			direct_users=True,
		),
		Relations.EDITOR: RelationDefinition(
			name=Relations.EDITOR,
			direct_users=True,
		),
		Relations.VIEWER: RelationDefinition(
			name=Relations.VIEWER,
			direct_users=True,
			union=[Relations.EDITOR, Relations.OWNER],
		),
		Relations.CAN_READ: RelationDefinition(
			name=Relations.CAN_READ,
			direct_users=False,
			union=[Relations.VIEWER, Relations.EDITOR, Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_READ,
		),
		Relations.CAN_WRITE: RelationDefinition(
			name=Relations.CAN_WRITE,
			direct_users=False,
			union=[Relations.EDITOR, Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_WRITE,
		),
		Relations.CAN_DELETE: RelationDefinition(
			name=Relations.CAN_DELETE,
			direct_users=False,
			union=[Relations.OWNER],
			inherit_from='parent',
			inherit_relation=Relations.CAN_DELETE,
		),
		'parent': RelationDefinition(
			name='parent',
			direct_users=False,
		),
	})

	# Group relations
	graph.define_type('group', {
		Relations.MEMBER: RelationDefinition(
			name=Relations.MEMBER,
			direct_users=True,
		),
		Relations.ADMIN: RelationDefinition(
			name=Relations.ADMIN,
			direct_users=True,
		),
	})

	# Organization/Department relations
	graph.define_type('department', {
		Relations.MEMBER: RelationDefinition(
			name=Relations.MEMBER,
			direct_users=True,
		),
		Relations.MANAGER: RelationDefinition(
			name=Relations.MANAGER,
			direct_users=True,
		),
		Relations.ADMIN: RelationDefinition(
			name=Relations.ADMIN,
			direct_users=True,
			union=[Relations.MANAGER],
		),
		'parent': RelationDefinition(
			name='parent',
			direct_users=False,
		),
	})

	return graph


class RelationshipChecker:
	"""
	Check permissions using relationship graph traversal.

	Implements Zanzibar-style check algorithm with:
	- Direct tuple lookup
	- Computed relation expansion
	- Userset traversal
	- Parent inheritance
	"""

	def __init__(
		self,
		store: RelationshipStore,
		graph: RelationshipGraph | None = None,
		max_depth: int = 10,
	):
		self.store = store
		self.graph = graph or create_default_graph()
		self.max_depth = max_depth
		self._cache: dict[tuple, CheckResult] = {}

	async def check(
		self,
		object_type: str,
		object_id: str,
		relation: str,
		subject_type: str,
		subject_id: str,
	) -> CheckResult:
		"""
		Check if subject has relation to object.

		Args:
			object_type: Type of object (document, folder, etc.)
			object_id: ID of the object
			relation: Relation to check (can_read, can_write, etc.)
			subject_type: Type of subject (user, group, etc.)
			subject_id: ID of the subject

		Returns:
			CheckResult with allowed status and path
		"""
		cache_key = (object_type, object_id, relation, subject_type, subject_id)

		if cache_key in self._cache:
			result = self._cache[cache_key]
			result.cached = True
			return result

		visited: set[tuple] = set()
		result = await self._check_recursive(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
			subject_type=subject_type,
			subject_id=subject_id,
			path=[],
			visited=visited,
			depth=0,
		)

		self._cache[cache_key] = result
		return result

	async def _check_recursive(
		self,
		object_type: str,
		object_id: str,
		relation: str,
		subject_type: str,
		subject_id: str,
		path: list[str],
		visited: set[tuple],
		depth: int,
	) -> CheckResult:
		"""Recursive check with cycle detection."""
		if depth > self.max_depth:
			logger.warning(f"Max depth reached checking {object_type}:{object_id}#{relation}")
			return CheckResult(allowed=False, path=path, evaluation_count=depth)

		check_tuple = (object_type, object_id, relation, subject_type, subject_id)
		if check_tuple in visited:
			return CheckResult(allowed=False, path=path, evaluation_count=depth)
		visited.add(check_tuple)

		current_path = path + [f"{object_type}:{object_id}#{relation}"]

		# 1. Direct tuple check
		if await self.store.exists(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
			subject_type=subject_type,
			subject_id=subject_id,
		):
			return CheckResult(
				allowed=True,
				path=current_path + [f"@{subject_type}:{subject_id}"],
				evaluation_count=depth + 1,
			)

		# 2. Check via userset (group membership)
		# Find tuples where subject has the relation via a group
		subjects = await self.store.get_subjects(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
		)

		for subj_type, subj_id, subj_relation in subjects:
			if subj_relation:
				# Check if our subject has the subject_relation to the intermediate subject
				# e.g., document:123#viewer@group:456#member
				# Check if user has member relation to group
				sub_result = await self._check_recursive(
					object_type=subj_type,
					object_id=subj_id,
					relation=subj_relation,
					subject_type=subject_type,
					subject_id=subject_id,
					path=current_path,
					visited=visited,
					depth=depth + 1,
				)
				if sub_result.allowed:
					return sub_result

		# 3. Check computed relations (union/intersection)
		definition = self.graph.get_definition(object_type, relation)
		if definition:
			# Check union - allowed if any of the union relations are satisfied
			if definition.union:
				for union_rel in definition.union:
					sub_result = await self._check_recursive(
						object_type=object_type,
						object_id=object_id,
						relation=union_rel,
						subject_type=subject_type,
						subject_id=subject_id,
						path=current_path,
						visited=visited,
						depth=depth + 1,
					)
					if sub_result.allowed:
						return sub_result

			# Check intersection - must satisfy all
			if definition.intersection:
				all_satisfied = True
				for inter_rel in definition.intersection:
					sub_result = await self._check_recursive(
						object_type=object_type,
						object_id=object_id,
						relation=inter_rel,
						subject_type=subject_type,
						subject_id=subject_id,
						path=current_path,
						visited=visited,
						depth=depth + 1,
					)
					if not sub_result.allowed:
						all_satisfied = False
						break
				if all_satisfied:
					return CheckResult(
						allowed=True,
						path=current_path + ["(intersection)"],
						evaluation_count=depth + 1,
					)

			# Check parent inheritance
			if definition.inherit_from and definition.inherit_relation:
				# Get parent objects
				parents = await self.store.get_subjects(
					object_type=object_type,
					object_id=object_id,
					relation=definition.inherit_from,
				)
				for parent_type, parent_id, _ in parents:
					sub_result = await self._check_recursive(
						object_type=parent_type,
						object_id=parent_id,
						relation=definition.inherit_relation,
						subject_type=subject_type,
						subject_id=subject_id,
						path=current_path,
						visited=visited,
						depth=depth + 1,
					)
					if sub_result.allowed:
						return sub_result

		return CheckResult(
			allowed=False,
			path=current_path,
			evaluation_count=depth + 1,
		)

	async def list_objects(
		self,
		subject_type: str,
		subject_id: str,
		relation: str,
		object_type: str | None = None,
	) -> list[tuple[str, str]]:
		"""List all objects where subject has the specified relation."""
		# Direct tuples
		direct = await self.store.get_objects(
			subject_type=subject_type,
			subject_id=subject_id,
			relation=relation,
			object_type=object_type,
		)

		# Also check via group membership
		# First find groups the user is a member of
		groups = await self.store.get_objects(
			subject_type=subject_type,
			subject_id=subject_id,
			relation=Relations.MEMBER,
			object_type='group',
		)

		group_objects = []
		for _, group_id in groups:
			# Find objects where group has the relation
			objs = await self.store.get_objects(
				subject_type='group',
				subject_id=group_id,
				relation=relation,
				object_type=object_type,
			)
			group_objects.extend(objs)

		return list(set(direct + group_objects))

	async def list_subjects(
		self,
		object_type: str,
		object_id: str,
		relation: str,
	) -> list[tuple[str, str]]:
		"""List all subjects with the specified relation to object."""
		direct_subjects = await self.store.get_subjects(
			object_type=object_type,
			object_id=object_id,
			relation=relation,
		)

		# Expand usersets to get final users
		result = []
		for subj_type, subj_id, subj_relation in direct_subjects:
			if subj_relation:
				# Get members of the userset
				members = await self.store.get_subjects(
					object_type=subj_type,
					object_id=subj_id,
					relation=subj_relation,
				)
				for mem_type, mem_id, _ in members:
					result.append((mem_type, mem_id))
			else:
				result.append((subj_type, subj_id))

		return list(set(result))

	def clear_cache(self):
		"""Clear the check cache."""
		self._cache.clear()


# Convenience functions

async def check_permission(
	db: Session,
	object_type: str,
	object_id: str,
	relation: str,
	subject_type: str,
	subject_id: str,
) -> bool:
	"""Quick permission check."""
	store = RelationshipStore(db)
	checker = RelationshipChecker(store)
	result = await checker.check(
		object_type=object_type,
		object_id=object_id,
		relation=relation,
		subject_type=subject_type,
		subject_id=subject_id,
	)
	return result.allowed


async def grant_permission(
	db: Session,
	object_type: str,
	object_id: str,
	relation: str,
	subject_type: str,
	subject_id: str,
	created_by: str | None = None,
) -> RelationTuple:
	"""Grant a permission by creating a tuple."""
	store = RelationshipStore(db)
	return await store.write(
		object_type=object_type,
		object_id=object_id,
		relation=relation,
		subject_type=subject_type,
		subject_id=subject_id,
		created_by=created_by,
	)


async def revoke_permission(
	db: Session,
	object_type: str,
	object_id: str,
	relation: str,
	subject_type: str,
	subject_id: str,
) -> bool:
	"""Revoke a permission by deleting a tuple."""
	store = RelationshipStore(db)
	return await store.delete(
		object_type=object_type,
		object_id=object_id,
		relation=relation,
		subject_type=subject_type,
		subject_id=subject_id,
	)
