# find-ecr-repository-action [![ts](https://github.com/int128/find-ecr-repository-action/actions/workflows/ts.yaml/badge.svg)](https://github.com/int128/find-ecr-repository-action/actions/workflows/ts.yaml)

This action finds an Amazon ECR repository.

## Getting Started

Here is an example workflow to build and push a container image to Amazon ECR.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: us-east-1
          role-to-assume: arn:aws:iam::123456789012:role/YourRoleName
      - id: ecr-repository
        uses: int128/find-ecr-repository-action@v1
        with:
          repository-name: hello-world
      - id: metadata
        uses: docker/metadata-action@v5
        with:
          images: ${{ steps.ecr-repository.outputs.repository-uri }}
      - uses: docker/build-push-action@v6
        id: build
        with:
          tags: ${{ steps.metadata.outputs.tags }}
```

## Specification

### Inputs

| Name                                 | Default                    | Description                                                                     |
| ------------------------------------ | -------------------------- | ------------------------------------------------------------------------------- |
| `registry-id`                        | -                          | AWS account ID of the repository. If not set, the default account will be used. |
| `repository-name`                    | (required)                 | Name of the repository in Amazon ECR                                            |
| `repository-not-found-error-message` | [action.yaml](action.yaml) | Error message to throw if the repository is not found                           |

### Outputs

| Name             | Description                         |
| ---------------- | ----------------------------------- |
| `repository-uri` | URI of the repository in Amazon ECR |
