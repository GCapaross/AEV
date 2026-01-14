# input and output file names
input_file = "input.txt"
output_file = "output.txt"

with open(input_file, "r", encoding="utf-8") as f:
    content = f.read()

# Insert a newline before every "A:"
formatted_content = content.replace(" A:", "\nA:")

with open(output_file, "w", encoding="utf-8") as f:
    f.write(formatted_content)

print("Formatted file written to output.txt")

