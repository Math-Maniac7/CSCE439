#!/bin/bash
# 本地设置检查脚本 - 验证路径、环境和配置

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "本地环境检查脚本"
echo "=========================================="
echo ""

# ==================== 配置区域 ====================
# HPRC FASTER系统路径（自动检测或手动设置）
# 自动检测当前目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# HPRC数据集路径
DATASET_BASE="/scratch/user/yafeili/704/dataset"

# 如果自动检测失败，可以手动设置：
# PROJECT_DIR="/scratch/user/yafeili/CSCE439"
# DATASET_BASE="/scratch/user/yafeili/704/dataset"
# ================================================

ERRORS=0
WARNINGS=0

# 检查1: Python环境
echo -e "${BLUE}[1/8] 检查Python环境...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Python已安装: $PYTHON_VERSION${NC}"
    PYTHON_PATH=$(which python3)
    echo "  Python路径: $PYTHON_PATH"
else
    echo -e "${RED}✗ Python3未安装或不在PATH中${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 检查2: Python包
echo -e "${BLUE}[2/8] 检查Python包...${NC}"
REQUIRED_PACKAGES=("numpy" "pandas" "sklearn" "lightgbm")
MISSING_PACKAGES=()

for package in "${REQUIRED_PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        VERSION=$(python3 -c "import $package; print(getattr($package, '__version__', 'unknown'))" 2>/dev/null)
        echo -e "${GREEN}✓ $package 已安装 (版本: $VERSION)${NC}"
    else
        echo -e "${RED}✗ $package 未安装${NC}"
        MISSING_PACKAGES+=("$package")
        ERRORS=$((ERRORS + 1))
    fi
done

# 检查ember（从GitHub安装的特殊包）
if python3 -c "import ember" 2>/dev/null; then
    echo -e "${GREEN}✓ ember 已安装${NC}"
else
    echo -e "${YELLOW}⚠ ember 未安装（需要从GitHub安装）${NC}"
    MISSING_PACKAGES+=("ember (git+https://github.com/endgameinc/ember.git)")
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# 检查3: 项目目录
echo -e "${BLUE}[3/8] 检查项目目录...${NC}"
if [ -d "$PROJECT_DIR" ]; then
    echo -e "${GREEN}✓ 项目目录存在: $PROJECT_DIR${NC}"
    
    # 检查关键文件
    KEY_FILES=(
        "train/train_all_models.py"
        "train/train_iterative.py"
        "train/load_datasets.py"
        "train/model_definitions.py"
    )
    
    for file in "${KEY_FILES[@]}"; do
        if [ -f "$PROJECT_DIR/$file" ]; then
            echo -e "  ${GREEN}✓ $file${NC}"
        else
            echo -e "  ${RED}✗ $file 不存在${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    done
else
    echo -e "${RED}✗ 项目目录不存在: $PROJECT_DIR${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 检查4: 数据集目录
echo -e "${BLUE}[4/8] 检查数据集目录...${NC}"
if [ -d "$DATASET_BASE" ]; then
    echo -e "${GREEN}✓ 数据集基础目录存在: $DATASET_BASE${NC}"
    
    # 检查各个数据集目录
    DATASET_DIRS=("ember_2017_2" "ember2018" "ember" "challenge_ds")
    FOUND_DATASETS=0
    
    for dir in "${DATASET_DIRS[@]}"; do
        if [ -d "$DATASET_BASE/$dir" ]; then
            echo -e "  ${GREEN}✓ $dir 存在${NC}"
            
            # 检查JSONL文件
            JSONL_COUNT=$(find "$DATASET_BASE/$dir" -name "train_features_*.jsonl" -type f 2>/dev/null | wc -l | tr -d ' ')
            if [ "$JSONL_COUNT" -gt 0 ]; then
                echo -e "    ${GREEN}  包含 $JSONL_COUNT 个JSONL文件${NC}"
            else
                echo -e "    ${YELLOW}  警告: 未找到train_features_*.jsonl文件${NC}"
                WARNINGS=$((WARNINGS + 1))
            fi
            
            FOUND_DATASETS=$((FOUND_DATASETS + 1))
        else
            echo -e "  ${YELLOW}⚠ $dir 不存在${NC}"
        fi
    done
    
    if [ $FOUND_DATASETS -eq 0 ]; then
        echo -e "${YELLOW}⚠ 未找到任何数据集目录${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}✗ 数据集基础目录不存在: $DATASET_BASE${NC}"
    echo -e "${YELLOW}  提示: 请修改脚本中的DATASET_BASE路径${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 检查5: 输出目录权限
echo -e "${BLUE}[5/8] 检查输出目录权限...${NC}"
OUTPUT_DIR="/scratch/user/yafeili/704/defenceOutput/test_output"
if [ -d "$OUTPUT_DIR" ]; then
    if [ -w "$OUTPUT_DIR" ]; then
        echo -e "${GREEN}✓ 输出目录可写: $OUTPUT_DIR${NC}"
    else
        echo -e "${RED}✗ 输出目录不可写: $OUTPUT_DIR${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    # 尝试创建
    if mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        echo -e "${GREEN}✓ 已创建输出目录: $OUTPUT_DIR${NC}"
        rmdir "$OUTPUT_DIR" 2>/dev/null || true
    else
        echo -e "${RED}✗ 无法创建输出目录: $OUTPUT_DIR${NC}"
        ERRORS=$((ERRORS + 1))
    fi
fi
echo ""

# 检查6: 代码语法检查
echo -e "${BLUE}[6/8] 检查Python代码语法...${NC}"
PYTHON_FILES=(
    "train/train_all_models.py"
    "train/train_iterative.py"
    "train/load_datasets.py"
    "train/model_definitions.py"
)

for file in "${PYTHON_FILES[@]}"; do
    if [ -f "$PROJECT_DIR/$file" ]; then
        if python3 -m py_compile "$PROJECT_DIR/$file" 2>/dev/null; then
            echo -e "  ${GREEN}✓ $file 语法正确${NC}"
        else
            echo -e "  ${RED}✗ $file 语法错误${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done
echo ""

# 检查7: 导入测试
echo -e "${BLUE}[7/8] 测试Python模块导入...${NC}"
cd "$PROJECT_DIR" 2>/dev/null || {
    echo -e "${RED}✗ 无法进入项目目录${NC}"
    ERRORS=$((ERRORS + 1))
    exit 1
}

# 测试导入关键模块
IMPORT_TESTS=(
    "from train.model_definitions import create_model"
    "from train.load_datasets import load_all_ember_datasets"
)

for import_test in "${IMPORT_TESTS[@]}"; do
    if python3 -c "$import_test" 2>/dev/null; then
        echo -e "  ${GREEN}✓ 导入成功: ${import_test%% import *}${NC}"
    else
        echo -e "  ${RED}✗ 导入失败: ${import_test%% import *}${NC}"
        python3 -c "$import_test" 2>&1 | head -3
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# 检查8: 最小功能测试
echo -e "${BLUE}[8/8] 最小功能测试...${NC}"
if [ $ERRORS -eq 0 ]; then
    # 测试创建模型
    if python3 -c "from train.model_definitions import create_model; m = create_model('model1', use_gpu=False); print('✓ 模型创建成功')" 2>/dev/null; then
        echo -e "  ${GREEN}✓ 模型创建功能正常${NC}"
    else
        echo -e "  ${RED}✗ 模型创建功能失败${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # 测试数据加载（如果有数据）
    if [ -d "$DATASET_BASE/ember2018" ] || [ -d "$DATASET_BASE/ember_2017_2" ] || [ -d "$DATASET_BASE/ember" ]; then
        echo -e "  ${YELLOW}⚠ 跳过数据加载测试（需要实际数据）${NC}"
    else
        echo -e "  ${YELLOW}⚠ 无法测试数据加载（数据集不存在）${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠ 跳过功能测试（存在前置错误）${NC}"
fi
echo ""

# 总结
echo "=========================================="
echo "检查完成"
echo "=========================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ 所有检查通过！环境配置正确。${NC}"
    echo ""
    echo "可以运行测试："
    echo "  bash train/test_local.sh"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ 检查完成，有 $WARNINGS 个警告，但可以运行测试${NC}"
    echo ""
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        echo "需要安装的包："
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo "  - $pkg"
        done
        echo ""
        echo "安装命令："
        echo "  pip3 install numpy pandas scikit-learn lightgbm"
        echo "  pip3 install git+https://github.com/endgameinc/ember.git"
    fi
    exit 0
else
    echo -e "${RED}✗ 检查失败，发现 $ERRORS 个错误，$WARNINGS 个警告${NC}"
    echo ""
    echo "请修复以下问题："
    
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        echo "1. 安装缺失的Python包："
        for pkg in "${MISSING_PACKAGES[@]}"; do
            echo "   - $pkg"
        done
        echo ""
        echo "   安装命令："
        echo "   pip3 install numpy pandas scikit-learn lightgbm"
        echo "   pip3 install git+https://github.com/endgameinc/ember.git"
        echo ""
    fi
    
    echo "2. 检查并修改脚本中的路径配置："
    echo "   - DATASET_BASE: $DATASET_BASE"
    echo "   - PROJECT_DIR: $PROJECT_DIR"
    echo ""
    exit 1
fi

