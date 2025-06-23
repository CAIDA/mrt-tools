rsync -avHSl --progress --include="*/" --include="2024.01/UPDATES/*" --exclude="*" archive.routeviews.org::routeviews/ dl/
find . -type d -empty -delete

