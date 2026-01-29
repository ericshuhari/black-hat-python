import cv2
import os

ROOT = '/home/majora/Desktop/pictures'
FACES = '/home/majora/Desktop/faces'
TRAIN = '/home/majora/Desktop/train'

def detect(srcdir=ROOT, tgtdir=FACES,train_dir=TRAIN):
    for fname in os.listdir(srcdir):
        if not fname.upper().endswith(('.PNG', '.JPG', '.JPEG')):
            continue
        fullname = os.path.join(srcdir, fname)
        newname = os.path.join(tgtdir,fname)
        img = cv2.imread(fullname)
        if img is None:
            continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        training = os.path.join(train_dir, 'haarcascade_frontalface_alt.xml')
        # load the pre-trained model for face detection in front-facing orientation
        cascade = cv2.CascadeClassifier(training)
        rects = cascade.detectMultiScale(gray, 1.3, 5)
        try:
            # in images where faces are found, return coordinates of bounding boxes
            if rects.any():
                print('Got a face')
                # convert (x, y, w, h) to (x1, y1, x2, y2)
                rects[:,2:] += rects[:,:2]
        except AttributeError:
            print(f'No faces found in {fname}.')
            continue

        # highlight the faces in image
        for x1, y1, x2, y2 in rects:
            # draw green rectangle around detected face
            cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
        # save the new image with highlighted faces to target directory
        cv2.imwrite(newname, img)

if __name__ == '__main__':
    detect()