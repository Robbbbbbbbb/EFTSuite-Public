import os
import cv2
import imutils
import numpy as np

# Read image, assume user uploads a resonably-aligned scan or uses the Crop/Rotate tool.
def align_image(img_path):
    # Return image as uploaded
    img = cv2.imread(img_path)
    if img is None:
        raise ValueError("Image not found")
    return img, True

# Logic to crop and rotate the image in case the user uploads something rotated 90/180/270 degrees or cropped out of alignment.
def apply_crop_and_rotate(img_path, rotate_angle, crop_rect):
    4# crop_rect: {x, y, w, h}
    print(f"Applying crop/rotate: path={img_path}, rot={rotate_angle}, rect={crop_rect}")
    img = cv2.imread(img_path)
    if img is None:
        raise ValueError("Image not found")
        
    # 1. Rotate
    if rotate_angle != 0:
        if rotate_angle == 90:
            img = cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
        elif rotate_angle == 180:
            img = cv2.rotate(img, cv2.ROTATE_180)
        elif rotate_angle == 270:
            img = cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)
            
    # 2. Crop
    x, y, w, h = int(crop_rect['x']), int(crop_rect['y']), int(crop_rect['w']), int(crop_rect['h'])
    
    # Ensure bounds
    if x < 0: x = 0
    if y < 0: y = 0
    if x + w > img.shape[1]: w = img.shape[1] - x
    if y + h > img.shape[0]: h = img.shape[0] - y
    
    if w > 0 and h > 0:
        img = img[y:y+h, x:x+w]
        
    print(f"Resulting cropped shape: {img.shape}")
    # For session simplicity, overwrite aligned.png
    return img

# Returns the default bounding boxes scaled to the image size
def get_default_boxes(img_shape):
    # Dimensions based on 8x8 inch card area
    # Rolls: 1.6" x 1.5" -> 0.20w, 0.1875h
    # Plain Thumbs: 1.0" x 2.0" -> 0.125w, 0.25h
    # Slaps: 3.0" x 2.0" -> 0.375w, 0.25h (Scaled to fit 8" width: 3+1+1+3 = 8)

    w_roll = 0.18  # Reduced by 10%
    h_roll = 0.16875 # Reduced by 10%
    w_plain = 0.10 # Reduced by 20%
    h_plain = 0.20 # Reduced by 20%
    w_slap = 0.375
    h_slap = 0.25
    
    y_row1 = 0.33
    y_row2 = 0.53
    y_row3 = 0.74
    
    defaults = [
        # Row 1: Right Hand Rolls
        {"id": "Right Thumb", "num": 1, "x": 0.0, "y": y_row1, "w": w_roll, "h": h_roll},
        {"id": "Right Index", "num": 2, "x": 0.20, "y": y_row1, "w": w_roll, "h": h_roll},
        {"id": "Right Middle", "num": 3, "x": 0.40, "y": y_row1, "w": w_roll, "h": h_roll},
        {"id": "Right Ring", "num": 4, "x": 0.60, "y": y_row1, "w": w_roll, "h": h_roll},
        {"id": "Right Little", "num": 5, "x": 0.80, "y": y_row1, "w": w_roll, "h": h_roll},

        # Row 2: Left Hand Rolls
        {"id": "Left Thumb", "num": 6, "x": 0.0, "y": y_row2, "w": w_roll, "h": h_roll},
        {"id": "Left Index", "num": 7, "x": 0.20, "y": y_row2, "w": w_roll, "h": h_roll},
        {"id": "Left Middle", "num": 8, "x": 0.40, "y": y_row2, "w": w_roll, "h": h_roll},
        {"id": "Left Ring", "num": 9, "x": 0.60, "y": y_row2, "w": w_roll, "h": h_roll},
        {"id": "Left Little", "num": 10, "x": 0.80, "y": y_row2, "w": w_roll, "h": h_roll},

        # Row 3: Plains
        {"id": "Left 4 Fingers", "num": 14, "x": 0.0, "y": y_row3, "w": w_slap, "h": h_slap},
        {"id": "Left Thumb Plain", "num": 12, "x": 0.375, "y": y_row3, "w": w_plain, "h": h_slap},
        {"id": "Right Thumb Plain", "num": 11, "x": 0.50, "y": y_row3, "w": w_plain, "h": h_slap},
        {"id": "Right 4 Fingers", "num": 13, "x": 0.625, "y": y_row3, "w": w_slap, "h": h_slap},
    ]
    
    h_img, w_img = img_shape[:2]
    boxes = []
    
    for box in defaults:
        boxes.append({
            "id": box["id"],
            "fp_number": box["num"],
            "x": int(box["x"] * w_img),
            "y": int(box["y"] * h_img),
            "w": int(box["w"] * w_img),
            "h": int(box["h"] * h_img)
        })
            
    return boxes
