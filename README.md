# spdx-java-tagvalue-store

SPDX store that supports serializing and deserializing SPDX tag/value files.

This library utilizes the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface) extending the `ExtendedSpdxStore` which allows for utilizing any underlying store which implements the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface).

The API documentation is available at:
<https://spdx.github.io/spdx-java-tagvalue-store/>

## Code quality badges

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=spdx-tagvalue-store&metric=bugs)](https://sonarcloud.io/dashboard?id=spdx-tagvalue-store)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=spdx-tagvalue-store&metric=security_rating)](https://sonarcloud.io/dashboard?id=spdx-tagvalue-store)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=spdx-tagvalue-store&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=spdx-tagvalue-store)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=spdx-tagvalue-store&metric=sqale_index)](https://sonarcloud.io/dashboard?id=spdx-tagvalue-store)

## Using the Library

This library is intended to be used in conjunction with the [SPDX Java Library](https://github.com/spdx/Spdx-Java-Library).

Create an instance of a store which implements the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface).  For example, the [InMemSpdxStore](https://github.com/spdx/Spdx-Java-Library/blob/master/src/main/java/org/spdx/storage/simple/InMemSpdxStore.java) is a simple in-memory storage suitable for simple file serializations and deserializations.

Create an instance of `TagValueStore(IModelStore baseStore)` passing in the instance of a store created above along with the format.

## Serializing and Deserializing

This library supports the `ISerializableModelStore` interface for serializing and deserializing files based on the format specified.

## Development Status

Mostly stable - although it has not been widely used.
