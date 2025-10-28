"""
Demo script showcasing Phase 3 code simplification enhancements.

This script contains intentional code patterns that trigger the 10 new
simplification rules implemented in Phase 3.
"""


# SIM300: Use '==' instead of 'not ... !='
def example_sim300(a, b):
    """Demonstrates negated inequality simplification."""
    if a == b:  # Should suggest: a == b
        pass


# SIM301: Use '!=' instead of 'not ... =='
def example_sim301(x, y):
    """Demonstrates negated equality simplification."""
    if x != y:  # Should suggest: x != y
        pass


# SIM222: De Morgan's Law - AND to OR
def example_sim222(flag1, flag2):
    """Demonstrates De Morgan's law simplification (AND to OR)."""
    if not (not flag1 and not flag2):  # Should suggest: flag1 or flag2
        pass


# SIM223: De Morgan's Law - OR to AND
def example_sim223(condition_a, condition_b):
    """Demonstrates De Morgan's law simplification (OR to AND)."""
    if not (not condition_a or not condition_b):  # Should suggest: condition_a and condition_b
        pass


# SIM106: Use guard clauses
def example_sim106(data):
    """Demonstrates guard clause opportunity."""
    if data:
        # Large processing block
        step1 = data.get("step1")
        step2 = data.get("step2")
        step3 = data.get("step3")
        return step1 + step2 + step3
    return None  # Should suggest using guard clause


# SIM116: Use dict.get() with default
def example_sim116(config):
    """Demonstrates dict.get() pattern."""
    if "timeout" in config:
        timeout = config["timeout"]
    else:
        timeout = 30  # Should suggest: timeout = config.get("timeout", 30)
    return timeout


# SIM110: Use all() instead of for loop
def example_sim110(items):
    """Demonstrates all() opportunity."""
    valid = True
    for item in items:
        if not item.is_valid():
            valid = False  # Should suggest: all(item.is_valid() for item in items)
    return valid


# SIM111: Use any() instead of for loop
def example_sim111(records):
    """Demonstrates any() opportunity."""
    found = False
    for record in records:
        if record.matches_criteria():
            found = True  # Should suggest: any(record.matches_criteria() for record in records)
    return found


# SIM118: Use 'key in dict' instead of 'key in dict.keys()'
def example_sim118(settings):
    """Demonstrates redundant dict.keys() usage."""
    if "debug" in settings:  # Should suggest: "debug" in settings
        return settings["debug"]
    return False


# Combination example - multiple Phase 3 rules
def complex_example(data, config):
    """Multiple Phase 3 issues in one function."""
    # SIM106: Guard clause opportunity
    if data:
        # SIM116: dict.get() pattern
        mode = config.get("mode", "default")

        # SIM118: Redundant .keys()
        enabled = data.get("enabled", True)

        # SIM300: Negated comparison
        if mode == "advanced":
            pass

        # SIM110: all() pattern
        valid = True
        for item in data.get("items", []):
            if not item:
                valid = False

        return mode, enabled, valid
    return None, None, None


class DemoClass:
    """Class demonstrating Phase 3 rules in context."""

    def __init__(self, options):
        """Initialize with options dict."""
        self.options = options

    def validate(self):
        """Validate all required options."""
        # SIM111: any() pattern
        has_error = False
        for key in ["name", "value", "type"]:
            if key not in self.options:
                has_error = True

        # SIM301: Negated equality
        return has_error

    def process(self, items):
        """Process items with guard clause pattern."""
        # SIM106: Guard clause
        if items:
            results = []
            for item in items:
                # SIM222: De Morgan's law
                if not (not item.active or not item.valid):
                    results.append(item.process())
            return results
        return []


def main():
    """Run demo examples."""

    # Run examples
    example_sim300(1, 1)
    example_sim301(1, 2)
    example_sim222(True, False)
    example_sim223(True, True)
    example_sim106({"step1": 1, "step2": 2, "step3": 3})
    example_sim116({"timeout": 60})


if __name__ == "__main__":
    main()
