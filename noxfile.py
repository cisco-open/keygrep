"""Keygrep Nox configuration"""
import shutil
import nox

@nox.session
def lint(session):
    """Lint source files and tests."""
    session.install("pylint", "nox", ".")
    session.run("pylint", "noxfile.py")
    session.run("pylint", *session.posargs, "src")
    session.run("pylint", *session.posargs, "tests")

@nox.session
def trailing_whitespace(session):
    """Check for trailing whitespace in tracked files."""
    result = session.run("git", "ls-files", silent=True, external=True)
    files = result.strip().splitlines()

    result = session.run(
        "grep", "-nE", r"\s$", *files, success_codes=[1], silent=True, external=True
    )

    if result:
        session.error("Trailing whitespace found:\n" + result)

@nox.session
def tests(session):
    """Run the unit tests. Downloads a set of test keys from the OpenSSH repo."""
    session.run("bash", "tests/download-test-keys.sh", "tests/test-keys", external=True)
    session.install("pytest")
    session.install(".")
    session.run("pytest", "-s", *session.posargs, "tests")

@nox.session
def build(session):
    """Build and check distributions with build and twine."""
    session.install("build", "twine")
    shutil.rmtree("dist", ignore_errors=True)
    shutil.rmtree("build", ignore_errors=True)
    session.run("python", "-m", "build")
    session.run("python", "-m", "twine", "check", "dist/*")
