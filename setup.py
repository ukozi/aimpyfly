from setuptools import setup, find_packages

setup(
	name="aimpyfly",  # Replace with your project name
	version="0.1.1",
	packages=find_packages(),  # Automatically finds packages in your project
	install_requires=[
		"asyncio==3.4.3",
		"colorama==0.4.6",
	],
	author="Lucas J. Chumley",
	author_email="Lucas@ukozi.com",
	description="An AIM client library for python.",
	long_description=open("README.md").read(),
	long_description_content_type="text/markdown",
	url="https://github.com/ukozi/aimpyfly",
	classifiers=[
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	python_requires=">=3.12",  # Ensure the correct Python version for your project
)