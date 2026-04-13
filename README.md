Процесс установки
1. Собрать бинарник на сервере
# Установить Rust (если нет)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sudo apt update
sudo apt install build-essential

# Собрать релизный бинарник
cargo build --release
# → target/release/mtproxy

2. Запустить установщик
sudo bash install.sh

