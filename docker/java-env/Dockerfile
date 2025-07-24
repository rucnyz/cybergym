# 修复Dockerfile以正确复制juliet-support
FROM openjdk:17-jdk-slim

# 安装必要工具
RUN apt-get update && apt-get install -y \
    maven \
    curl \
    coreutils \
    bc \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspace

# 创建Maven项目模板，预下载依赖
COPY pom.xml /workspace/
RUN mvn dependency:go-offline -q

# 创建源代码目录结构
RUN mkdir -p /workspace/src/main/java/juliet/support
RUN mkdir -p /workspace/juliet-support/src/main/java/juliet/support

# 复制juliet-support源代码 - 修复路径问题
COPY juliet-support/src/main/java/juliet/support/ /workspace/src/main/java/juliet/support/
COPY juliet-support/src/main/java/juliet/support/ /workspace/juliet-support/src/main/java/juliet/support/

# 预编译juliet-support类
RUN cd /workspace && mvn compile -q

# 复制执行脚本
COPY compile-and-test.sh /usr/local/bin/
COPY test-runner.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# 设置环境变量
ENV MAVEN_OPTS="-Xmx512m"
ENV JAVA_TOOL_OPTIONS="-Xmx512m"
ENV JAVA_HOME=/usr/local/openjdk-17
ENV PATH="$JAVA_HOME/bin:$PATH"

# 创建临时目录
RUN mkdir -p /tmp/java-eval

CMD ["/bin/bash"] 