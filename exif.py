from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def get_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            print("No EXIF metadata found.")
            return

        print(f"EXIF data for {image_path}:")
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                gps_data = {}
                for gps_id in value:
                    gps_tag = GPSTAGS.get(gps_id, gps_id)
                    gps_data[gps_tag] = value[gps_id]
                print(f"{tag_name}: {gps_data}")
            else:
                print(f"{tag_name}: {value}")

    except FileNotFoundError:
        print("The specified image file does not exist.")
    except Exception as e:
        print(f"Error reading EXIF data: {e}")

if __name__ == "__main__":
    image_path = input("Enter the path to the image file: ")
    get_exif_data(image_path)
