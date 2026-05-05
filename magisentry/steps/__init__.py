"""Seven scan layers. Each module exposes:
    run(ecosystem, package, config, t, ctx) -> StepResult
ecosystem: "pip" | "npm"
package: "name" or "name==version" / "name@version"
ctx: shared mutable dict (step 4 stores artifact / extracted_dir for steps 5-7)
"""
