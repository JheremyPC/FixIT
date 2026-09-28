from app.services.assignment import AssignmentService


def test_weight_defaults_are_complete():
    # The algorithm has an explicit configurable factor for every required signal.
    keys = AssignmentService.__init__.__globals__["WEIGHT_DEFAULTS"]
    assert {"assignment.rating", "assignment.sla", "assignment.speed", "assignment.specialty", "assignment.resolved", "assignment.reopened", "assignment.load_penalty"} <= set(keys)

