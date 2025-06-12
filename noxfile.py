"""Keygrep Nox configuration"""
import shutil
import nox

@nox.session
def lint(session):
    """Lint source files."""
    #session.install("-r", "requirements.txt")
    session.install("pylint", "nox")
    session.run("pylint", "noxfile.py")
    session.run("pylint", *session.posargs, "src")

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

# Tests have not yet been formalized due to potential issues with committing
# key data. Some utility scripts for manual testing are included under tests/
#@nox.session(python=["3.9", "3.10", "3.11"])
#def tests(session):
#    """Run the unit tests."""
#    session.install("pytest")
#    session.install(".")
#    session.run("pylint", *session.posargs, "tests")
#    session.run("bash", "tests/generate-test-keys.sh", "tests/test-keys", external=True)
#    session.run("pytest", *session.posargs, "tests")

@nox.session
def build(session):
    """Build and check distributions with build and twine."""
    session.install("build", "twine")
    shutil.rmtree("dist", ignore_errors=True)
    shutil.rmtree("build", ignore_errors=True)
    session.run("python", "-m", "build")
    session.run("python", "-m", "twine", "check", "dist/*")
