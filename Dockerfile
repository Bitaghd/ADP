# syntax=docker/dockerfile:1

ARG PROJECT_NAME=AnomalyDetection.Api

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG PROJECT_NAME
WORKDIR /src

COPY TrafficAnomalyDetection.slnx ./
COPY src ./src

RUN dotnet restore "src/${PROJECT_NAME}/${PROJECT_NAME}.csproj"
RUN dotnet publish "src/${PROJECT_NAME}/${PROJECT_NAME}.csproj" \
    --configuration Release \
    --output /out \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /out ./
ENTRYPOINT ["dotnet"]
