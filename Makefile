compile:
	meson compile -C build

setup:
	meson setup --reconfigure build --native-file meson-native.txt --wrap-mode nodownload

format:
	find . -type f \( -name "*.cpp" -o -name "*.cc" -o -name "*.hpp" -o -name "*.h" \) | grep -E '/src/|/tests/|/include/' | xargs clang-format -i
