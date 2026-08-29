from pathlib import Path
from llama_cpp import Llama
import sys
import time


MODEL_PATH = Path(
    r"C:\Dev\halon\models\Phi-4-mini-instruct-Q4_K_M.gguf"
)


def main() -> None:

    print()
    print("=======================================")
    print(" HALON REASONING ENGINE SMOKE TEST")
    print("=======================================")
    print()

    if not MODEL_PATH.exists():
        print(f"FAIL: Model not found:")
        print(MODEL_PATH)
        sys.exit(1)

    print(f"Model: {MODEL_PATH.name}")
    print()
    print("Loading Phi-4 Mini...")
    print()

    load_start = time.perf_counter()

    try:
        model = Llama(
            model_path=str(MODEL_PATH),
            n_ctx=4096,
            n_threads=8,
            verbose=False,
        )

    except Exception as error:
        print("FAIL: Model could not be loaded.")
        print()
        print(error)
        sys.exit(1)

    load_seconds = time.perf_counter() - load_start

    print(
        f"Model loaded in {load_seconds:.2f} seconds."
    )
    print()
    print("Running local inference...")
    print()

    inference_start = time.perf_counter()

    try:
        response = model.create_chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are the HALON Reasoning Engine."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Respond with exactly: "
                        "HALON reasoning engine online."
                    ),
                },
            ],
            temperature=0.0,
            max_tokens=32,
        )

    except Exception as error:
        print("FAIL: Inference failed.")
        print()
        print(error)
        sys.exit(1)

    inference_seconds = (
        time.perf_counter() - inference_start
    )

    try:
        answer = response["choices"][0]["message"]["content"]
        answer = answer.strip()

    except Exception:
        print("FAIL: Unexpected response structure.")
        print()
        print(response)
        sys.exit(1)

    print("Model response:")
    print()
    print(answer)
    print()

    print(
        f"Inference completed in "
        f"{inference_seconds:.2f} seconds."
    )
    print()

    expected = "HALON reasoning engine online."

    if answer == expected:

        print("PASS: Local inference is operational.")

    else:

        print(
            "PARTIAL PASS: The model generated locally, "
            "but did not follow the exact-output instruction."
        )

        print()
        print(f"Expected: {expected}")

    print()
    print("=======================================")
    print(" SMOKE TEST COMPLETE")
    print("=======================================")
    print()


if __name__ == "__main__":
    main()