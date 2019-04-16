import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="access-checker-sbhalodia",
    version="1.0.3",
    author="Sandeep Bhalodia",
    author_email="sandeeep.says@gmail.com",
    description="Access checker for Cisco ACL(extended ACL)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sanp2017/access-checker-sbhalodia.git",
    packages=["access_checker", "access_checker.templates"],
    package_data={'access_checker': ['templates/*.html']},
    include_package_data=True,
    install_requires=["flask", "flask_bootstrap"],
    entry_points={
        "console_scripts": [
            "access-checker-cli=access_checker.main:main",
            "access-checker-gui=access_checker.gui_access_checker:create_app"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
