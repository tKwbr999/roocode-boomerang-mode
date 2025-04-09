import unittest
import subprocess
import sys
import os

class TestHelloWorld(unittest.TestCase):

    def test_hello_world_output(self):
        """
        main.py を実行した際の標準出力が 'hello world\\n' であることを確認する
        """
        # main.py の絶対パスを取得
        # __file__ は test_main.py のパスを指す
        current_dir = os.path.dirname(__file__)
        main_script_path = os.path.join(current_dir, 'main.py')

        # python インタープリタで main.py を実行し、標準出力をキャプチャ
        try:
            result = subprocess.run(
                [sys.executable, main_script_path], # 実行するコマンドと引数
                capture_output=True,  # 標準出力と標準エラー出力をキャプチャ
                text=True,            # 出力をテキストとして扱う
                check=True,           # 終了コードが0以外ならCalledProcessErrorを送出
                encoding='utf-8'      # 出力のエンコーディングを指定
            )
            # 標準出力が期待通りか検証
            self.assertEqual(result.stdout, "hello world\n")
        except FileNotFoundError:
            self.fail(f"Python executable not found at {sys.executable}")
        except subprocess.CalledProcessError as e:
            self.fail(f"main.py execution failed with error code {e.returncode}: {e.stderr}")
        except Exception as e:
            self.fail(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    unittest.main()
