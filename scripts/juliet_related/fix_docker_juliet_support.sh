#!/bin/bash

set -e

echo "🔧 修复Docker juliet-support路径问题..."

# 1. 修复Docker构建上下文中的juliet-support路径
echo "📁 准备juliet-support源码..."

# 确保Docker构建上下文有正确的juliet-support文件
DOCKER_JULIET_SUPPORT="cybergym/docker/java-env/juliet-support/src/main/java/juliet/support"
mkdir -p "$DOCKER_JULIET_SUPPORT"

# 从实际的juliet-support目录复制源码
if [ -d "juliet-support/src/main/java/juliet/utils" ]; then
    echo "✓ 发现juliet-support源码在 utils 目录"
    cp -r juliet-support/src/main/java/juliet/utils/* "$DOCKER_JULIET_SUPPORT/"
    echo "✓ 复制juliet-support源码到Docker构建上下文"
elif [ -d "juliet-support/src/main/java/juliet/support" ]; then
    echo "✓ 发现juliet-support源码在 support 目录"
    cp -r juliet-support/src/main/java/juliet/support/* "$DOCKER_JULIET_SUPPORT/"
    echo "✓ 复制juliet-support源码到Docker构建上下文"
else
    echo "❌ 找不到juliet-support源码"
    exit 1
fi

# 2. 检查是否有IO.java等关键文件
if [ ! -f "$DOCKER_JULIET_SUPPORT/IO.java" ]; then
    echo "⚠️ 创建基本的IO.java文件"
    cat > "$DOCKER_JULIET_SUPPORT/IO.java" << 'EOF'
package juliet.support;

public class IO {
    public static void writeLine(String line) {
        System.out.println(line);
    }
    
    public static void writeString(String str) {
        System.out.print(str);
    }
}
EOF
fi

# 3. 重建Docker镜像
echo "🐳 重建Docker镜像..."
cd cybergym/docker/java-env

# 停止并删除现有容器
echo "🧹 清理现有Docker镜像和容器..."
docker stop $(docker ps -q --filter ancestor=juliet-java-local) 2>/dev/null || true
docker rm $(docker ps -aq --filter ancestor=juliet-java-local) 2>/dev/null || true
docker rmi juliet-java-local 2>/dev/null || true

# 构建新镜像
echo "🔨 构建新的Docker镜像..."
docker build -t juliet-java-local .

if [ $? -eq 0 ]; then
    echo "✅ Docker镜像构建成功！"
    
    # 测试镜像
    echo "🧪 测试Docker镜像..."
    docker run --rm juliet-java-local bash -c "
        echo '=== Java版本 ==='
        java -version
        echo '=== Maven版本 ==='
        mvn -version
        echo '=== juliet-support文件 ==='
        ls -la /workspace/src/main/java/juliet/support/
        echo '=== 测试编译juliet-support ==='
        cd /workspace
        javac src/main/java/juliet/support/*.java && echo '✅ juliet-support编译成功' || echo '❌ juliet-support编译失败'
    "
else
    echo "❌ Docker镜像构建失败"
    exit 1
fi

cd ../../..

# 4. 清理临时文件
echo "🧹 清理临时文件..."
rm -rf cybergym/docker/java-env/juliet-support

echo "🎉 Docker juliet-support修复完成！"
echo ""
echo "下一步："
echo "1. 运行 'python cwe_batch_tester.py --help' 查看新的批量测试选项"
echo "2. 或运行 'python cwe_batch_tester.py --cwe CWE835' 测试CWE-835" 