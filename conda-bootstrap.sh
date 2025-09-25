# Install Conda
PREFIX="$HOME/miniconda3"

# 1) Install Miniconda if missing
if [ ! -d "$PREFIX" ]; then
  mkdir -p "$PREFIX"
  curl -fsSL https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -o "$PREFIX/miniconda.sh"
  bash "$PREFIX/miniconda.sh" -b -u -p "$PREFIX"
  rm "$PREFIX/miniconda.sh"
  "$PREFIX/bin/conda" init --all
fi

# Install mamba
conda config --add channels conda-forge
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda install -n base mamba -y

# Create environment
# mamba env create -f environment.yml

# Register kernels
# "$PREFIX/bin/conda" run -n watson python -m ipykernel install --user --name "watson" --display-name "Python (watson)"

# echo "Done. Open a new shell to use 'conda activate'."