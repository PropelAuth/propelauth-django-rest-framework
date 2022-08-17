from setuptools import find_packages, setup
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="propelauth-django-rest-framework",
    version="1.0.1",
    description="A library for managing authentication in Django Rest Framework",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/propelauth/propelauth-django-rest-framework",
    packages=find_packages(include=["propelauth_django_rest_framework"]),
    author="PropelAuth",
    author_email="support@propelauth.com",
    license="MIT",
    install_requires=["django", "djangorestframework", "propelauth-py", "requests"],
    setup_requires=["pytest-runner"],
    tests_require=["pytest==4.4.1"],
    test_suite="tests",
)
