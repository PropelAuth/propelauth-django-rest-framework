import pathlib
import sys

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

# See https://pytest-runner.readthedocs.io/en/latest/#conditional-requirement
needs_pytest = {"pytest", "test", "ptr"}.intersection(sys.argv)
pytest_runner = ["pytest-runner"] if needs_pytest else []

setup(
    name="propelauth-django-rest-framework",
    version="2.1.19",
    description="A library for managing authentication in Django Rest Framework",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/propelauth/propelauth-django-rest-framework",
    packages=find_packages(include=["propelauth_django_rest_framework"]),
    author="PropelAuth",
    author_email="support@propelauth.com",
    license="MIT",
    install_requires=[
        "django",
        "djangorestframework",
        "propelauth-py==3.1.19",
        "requests",
    ],
    setup_requires=pytest_runner,
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
)
