import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import io
import math
import json
import os
import zlib, base64
from PIL import Image, ImageTk

IMGBB_API_KEY = "IMGBB_API_KEY"
UPLOAD_URL = "https://api.imgbb.com/1/upload"

MAX_SIDE = 2000

def file_to_image(file_bytes):
    header = len(file_bytes).to_bytes(4, byteorder='big')
    data = header + file_bytes
    total_length = len(data)
    side = math.ceil(math.sqrt(total_length / 3))
    total_capacity = side * side * 3
    padded_data = data + bytes(total_capacity - total_length)
    img = Image.frombytes("RGB", (side, side), padded_data)
    return img

def image_to_file(image):
    data = image.tobytes()
    file_size = int.from_bytes(data[:4], byteorder='big')
    file_bytes = data[4:4+file_size]
    return file_bytes

def segment_to_image(segment_bytes, seg_index, total_segments):
    header = (seg_index.to_bytes(4, byteorder='big') +
              total_segments.to_bytes(4, byteorder='big') +
              len(segment_bytes).to_bytes(4, byteorder='big'))
    data = header + segment_bytes
    total_length = len(data)
    side = math.ceil(math.sqrt(total_length / 3))
    if side > MAX_SIDE:
        raise ValueError("Segment too large for MAX_SIDE, logic error")
    total_capacity = side * side * 3
    padded_data = data + bytes(total_capacity - total_length)
    img = Image.frombytes("RGB", (side, side), padded_data)
    return img

def image_to_segment(image):
    data = image.tobytes()
    if len(data) < 12:
        raise ValueError("Image too small to contain a valid header")
    seg_index = int.from_bytes(data[0:4], byteorder='big')
    total_segments = int.from_bytes(data[4:8], byteorder='big')
    seg_length = int.from_bytes(data[8:12], byteorder='big')
    segment_bytes = data[12:12+seg_length]
    return seg_index, total_segments, segment_bytes

class FileImageTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("InfStorage")
        self.root.geometry("700x170")
        
        self.label = tk.Label(root, text="Upload a file to convert it into a unique code")
        self.label.pack(pady=10)
        
        self.upload_button = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_button.pack(pady=5)
        
        self.link_entry = tk.Entry(root, width=80)
        self.link_entry.pack(pady=5)
        
        self.decode_button = tk.Button(root, text="Download and Reconstruct File", command=self.download_and_reconstruct)
        self.decode_button.pack(pady=5)
    
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        file_name = os.path.basename(file_path)
        
        required_side = math.ceil(math.sqrt((len(file_bytes) + 4) / 3))
        
        if required_side <= MAX_SIDE:
            img = file_to_image(file_bytes)
            mode = "u"
        else:
            SEGMENT_CAPACITY = MAX_SIDE * MAX_SIDE * 3 - 12
            segments = [file_bytes[i:i+SEGMENT_CAPACITY] for i in range(0, len(file_bytes), SEGMENT_CAPACITY)]
            total_segments = len(segments)
            imgbb_links = []
            for idx, seg in enumerate(segments):
                try:
                    seg_img = segment_to_image(seg, idx, total_segments)
                except Exception as e:
                    messagebox.showerror("Error", f"Error in segment {idx}: {e}")
                    return
                buffer = io.BytesIO()
                seg_img.save(buffer, format="PNG")
                buffer.seek(0)
                response = requests.post(UPLOAD_URL, files={"image": buffer}, params={"key": IMGBB_API_KEY})
                if response.status_code == 200:
                    link = response.json()["data"]["url"]
                    imgbb_links.append(link)
                else:
                    error_message = response.json() if response.content else "No response"
                    messagebox.showerror("Error", f"Segment {idx+1}: Unable to upload the image:\n{error_message}")
                    return
            mode = "s"
        
        if mode == "u":
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            buffer.seek(0)
            response = requests.post(UPLOAD_URL, files={"image": buffer}, params={"key": IMGBB_API_KEY})
            if response.status_code == 200:
                image_url = response.json()["data"]["url"]
            else:
                error_message = response.json() if response.content else "No response"
                messagebox.showerror("Error", f"Unable to upload the image:\n{error_message}")
                return
            final_data = {"m": "u", "u": image_url, "n": file_name}
            buffer.seek(0)
            img_tk = ImageTk.PhotoImage(Image.open(buffer))
        else:
            final_data = {"m": "s", "s": imgbb_links, "n": file_name}
            try:
                first_link = imgbb_links[0]
                resp = requests.get(first_link)
                if resp.status_code == 200:
                    buffer = io.BytesIO(resp.content)
                    img_seg = Image.open(buffer)
                    img_seg_tk = ImageTk.PhotoImage(img_seg)
            except Exception as e:
                print("Error displaying the first segment image:", e)
        
        final_json = json.dumps(final_data, separators=(',', ':'))
        compressed = zlib.compress(final_json.encode('utf-8'))
        encoded = base64.urlsafe_b64encode(compressed).decode('utf-8')
        
        self.link_entry.delete(0, tk.END)
        self.link_entry.insert(0, encoded)
        messagebox.showinfo("Success", "File processed and unique code generated!")
    
    def download_and_reconstruct(self):
        encoded = self.link_entry.get()
        if not encoded:
            messagebox.showerror("Error", "Please enter a valid code")
            return
        
        try:
            compressed = base64.urlsafe_b64decode(encoded)
            json_str = zlib.decompress(compressed).decode('utf-8')
            data = json.loads(json_str)
        except Exception as e:
            messagebox.showerror("Error", f"Error decoding the code: {e}")
            return
        
        mode = data.get("m")
        file_name = data.get("n", "reconstructed_file")
        
        if mode == "u":
            url = data.get("u")
            if not url:
                messagebox.showerror("Error", "Invalid code (URL missing)")
                return
            response = requests.get(url)
            if response.status_code == 200:
                buffer = io.BytesIO(response.content)
                try:
                    img = Image.open(buffer)
                except Exception as e:
                    messagebox.showerror("Error", f"Unable to open the image: {e}")
                    return
                file_bytes = image_to_file(img)
            else:
                messagebox.showerror("Error", "Unable to download the image")
                return
        elif mode == "s":
            segments_links = data.get("s")
            if not segments_links:
                messagebox.showerror("Error", "Invalid code (missing segments list)")
                return
            segments_data = {}
            for idx, url in enumerate(segments_links):
                response = requests.get(url)
                if response.status_code == 200:
                    buffer = io.BytesIO(response.content)
                    try:
                        img = Image.open(buffer)
                    except Exception as e:
                        messagebox.showerror("Error", f"Unable to open the image for segment {idx}: {e}")
                        return
                    try:
                        seg_index, total_segments, seg_bytes = image_to_segment(img)
                    except Exception as e:
                        messagebox.showerror("Error", f"Unable to decode segment {idx}: {e}")
                        return
                    segments_data[seg_index] = seg_bytes
                else:
                    messagebox.showerror("Error", f"Unable to download segment {idx+1}")
                    return
            file_bytes = b""
            for i in range(len(segments_data)):
                if i not in segments_data:
                    messagebox.showerror("Error", f"Missing segment {i}")
                    return
                file_bytes += segments_data[i]
        else:
            messagebox.showerror("Error", "Invalid code (unknown mode)")
            return
        
        directory = filedialog.askdirectory(title="Select destination directory")
        if not directory:
            return
        save_path = os.path.join(directory, file_name)
        with open(save_path, "wb") as f:
            f.write(file_bytes)
        messagebox.showinfo("Success", f"File reconstructed and saved in:\n{save_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileImageTransferApp(root)
    root.mainloop()