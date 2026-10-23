"""pyHanko's default diff policy, except that new visible signature fields
after a certification are accepted, as Acrobat does."""
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    FormUpdatingRule,
    GenericFieldModificationRule,
    SigFieldCreationRule,
    SigFieldModificationRule,
    StandardDiffPolicy,
)

ACROBAT_POLICY = StandardDiffPolicy(
    global_rules=DEFAULT_DIFF_POLICY.global_rules,
    form_rule=FormUpdatingRule(
        field_rules=[
            SigFieldCreationRule(allow_new_visible_after_certify=True),
            SigFieldModificationRule(),
            GenericFieldModificationRule(),
        ],
    ),
)
